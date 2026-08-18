/**
 * @description Test class for TrxSec_DetectHighRiskBulkAPI
 */
@isTest
private class TrxSec_DetectHighRiskBulkAPITest {
    private class StubProvider implements TrxSec_DetectHighRiskBulkAPI.Provider {
        private final List<String> highRiskLevels;
        private final Map<String, List<String>> confidentialFieldsByEntity;
        private final Set<String> requestedEntities = new Set<String>();

        StubProvider(List<String> highRiskLevels, Map<String, List<String>> confidentialFieldsByEntity) {
            this.highRiskLevels = highRiskLevels;
            this.confidentialFieldsByEntity = confidentialFieldsByEntity;
        }

        public List<String> getHighRiskLevels() {
            return highRiskLevels == null ? new List<String>() : highRiskLevels;
        }

        public List<String> getConfidentialFields(String entity, List<String> ignoredHighRiskLevels) {
            requestedEntities.add(entity.toLowerCase());
            List<String> fields = confidentialFieldsByEntity == null
                ? null
                : confidentialFieldsByEntity.get(entity.toLowerCase());
            return fields == null ? new List<String>() : fields;
        }
    }

    private static StubProvider useProvider(
        List<String> highRiskLevels,
        Map<String, List<String>> confidentialFieldsByEntity
    ) {
        StubProvider stub = new StubProvider(highRiskLevels, confidentialFieldsByEntity);
        TrxSec_DetectHighRiskBulkAPI.provider = stub;
        return stub;
    }

    private static StubProvider useProvider(List<String> highRiskLevels, String entity, List<String> confidentialFields) {
        return useProvider(
            highRiskLevels,
            new Map<String, List<String>>{ entity => confidentialFields }
        );
    }

    private static Boolean evaluateQuery(String query) {
        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = query;
        return new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
    }

    private static Set<String> extractedEntities(String query) {
        Set<String> entities = new Set<String>();
        for (String entity : TrxSec_DetectHighRiskBulkAPI.extractEntitiesFromQuery(query)) {
            entities.add(entity.toLowerCase());
        }
        return entities;
    }

    @isTest
    static void testReturnsFalseWhenNoHighRiskLevelsConfigured() {
        useProvider(new List<String>(), 'account', new List<String>());

        System.assertEquals(
            false,
            evaluateQuery('SELECT Id, Name FROM Account'),
            'Should allow when no high-risk levels are configured'
        );
    }

    @isTest
    static void testNullQueryHandled() {
        useProvider(new List<String>{'HIGH'}, 'account', new List<String>{'ssn__c'});

        System.assertEquals(false, evaluateQuery(null), 'Null Query should be handled safely');
    }

    @isTest
    static void testEmptyQueryHandled() {
        useProvider(new List<String>{'HIGH'}, 'account', new List<String>{'ssn__c'});

        System.assertEquals(false, evaluateQuery(''), 'Empty Query should be handled safely');
    }

    @isTest
    static void testDetectsConfidentialFieldInQuery() {
        useProvider(new List<String>{'HIGH'}, 'account', new List<String>{'ssn__c'});

        System.assertEquals(
            true,
            evaluateQuery('SELECT Id, SSN__c FROM Account'),
            'Should detect confidential field in query'
        );
    }

    @isTest
    static void testDoesNotDetectWhenFieldNotPresent() {
        useProvider(new List<String>{'HIGH'}, 'account', new List<String>{'ssn__c'});

        System.assertEquals(
            false,
            evaluateQuery('SELECT Id, Name FROM Account'),
            'Should not detect when field is not present'
        );
    }

    @isTest
    static void testQueryWithWhereClause() {
        useProvider(new List<String>{'HIGH'}, 'account', new List<String>{'ssn__c'});

        System.assertEquals(
            true,
            evaluateQuery('SELECT Id, SSN__c FROM Account WHERE CreatedDate > TODAY'),
            'Should detect confidential field in query with WHERE clause'
        );
    }

    @isTest
    static void testQueryWithoutFromClause() {
        useProvider(new List<String>{'HIGH'}, 'account', new List<String>{'ssn__c'});

        System.assertEquals(false, evaluateQuery('SELECT Id, Name'), 'Should handle query without FROM clause');
    }

    @isTest
    static void testDetectsFieldOnEntityFollowingRelationshipSubquery() {
        StubProvider stub = useProvider(new List<String>{'HIGH'}, 'account', new List<String>{'ssn__c'});

        System.assertEquals(
            true,
            evaluateQuery('SELECT SSN__c, (SELECT Id FROM Contacts) FROM Account'),
            'The top-level entity must be classified even when a subquery FROM comes first'
        );
        System.assert(
            stub.requestedEntities.contains('account'),
            'Expected the top-level entity to be classified, requested: ' + stub.requestedEntities
        );
    }

    @isTest
    static void testDetectsFieldOnChildEntityOfRelationshipSubquery() {
        useProvider(new List<String>{'HIGH'}, 'contact', new List<String>{'ssn__c'});

        System.assertEquals(
            true,
            evaluateQuery('SELECT Id, (SELECT Id, SSN__c FROM Contacts) FROM Account'),
            'A relationship subquery should be classified against the child entity'
        );
    }

    @isTest
    static void testDetectsFieldOnSemiJoinEntity() {
        useProvider(new List<String>{'HIGH'}, 'contact', new List<String>{'ssn__c'});

        System.assertEquals(
            true,
            evaluateQuery('SELECT Id FROM Account WHERE Id IN (SELECT AccountId FROM Contact WHERE SSN__c != NULL)'),
            'A semi-join subquery entity should be classified'
        );
    }

    @isTest
    static void testClassifiesEveryEntityInQuery() {
        // No entity has classified fields, so evaluation cannot short-circuit before the last one
        StubProvider stub = useProvider(new List<String>{'HIGH'}, new Map<String, List<String>>());

        evaluateQuery(
            'SELECT Id, (SELECT Id FROM Contacts) FROM Account WHERE Id IN (SELECT AccountId FROM Opportunity)'
        );

        System.assertEquals(
            new Set<String>{'account', 'contact', 'opportunity'},
            stub.requestedEntities,
            'Every entity in the query should be classified'
        );
    }

    @isTest
    static void testExtractsTopLevelEntityAheadOfRelationshipSubquery() {
        System.assertEquals(
            new Set<String>{'account', 'contact'},
            extractedEntities('SELECT SSN__c, (SELECT Id FROM Contacts) FROM Account'),
            'Both the top-level entity and the subquery child entity should be extracted'
        );
    }

    @isTest
    static void testExtractsEntityWithAlias() {
        System.assertEquals(
            new Set<String>{'account'},
            extractedEntities('SELECT a.Id FROM Account a WHERE a.Name != NULL'),
            'An alias should not be mistaken for an entity'
        );
    }

    @isTest
    static void testIgnoresParenthesesThatDoNotOpenSubqueries() {
        System.assertEquals(
            new Set<String>{'account'},
            extractedEntities('SELECT COUNT() FROM Account WHERE (Name != NULL OR Type != NULL)'),
            'Non-subquery parentheses should not affect entity extraction'
        );
    }

    @isTest
    static void testIgnoresFromInsideStringLiteral() {
        System.assertEquals(
            new Set<String>{'account'},
            extractedEntities('SELECT Id FROM Account WHERE Name = \'select Id from Contact\''),
            'A FROM inside a string literal should not be treated as a clause'
        );
    }

    @isTest
    static void testExtractsEntityFromPolymorphicTypeOfQuery() {
        System.assertEquals(
            new Set<String>{'event'},
            extractedEntities('SELECT TYPEOF What WHEN Account THEN Phone ELSE Name END FROM Event'),
            'A TYPEOF block should not shadow the FROM clause'
        );
    }

    @isTest
    static void testExtractsEntityFromSemiJoinInsideRelationshipSubquery() {
        System.assertEquals(
            new Set<String>{'account', 'contact', 'case'},
            extractedEntities(
                'SELECT Id, (SELECT Id FROM Contacts WHERE Id IN (SELECT ContactId FROM Case)) FROM Account'
            ),
            'A semi-join nested inside a relationship subquery should still be extracted'
        );
    }

    @isTest
    static void testExtractsEntityWithTrailingClauses() {
        System.assertEquals(
            new Set<String>{'account'},
            extractedEntities(
                'SELECT Id FROM Account WHERE CreatedDate = LAST_N_DAYS:5 WITH SECURITY_ENFORCED '
                    + 'ORDER BY Name LIMIT 200 OFFSET 10 FOR VIEW'
            ),
            'Trailing SOQL clauses should not affect entity extraction'
        );
    }

    @isTest
    static void testIgnoresTargetThatIsNotAnIdentifier() {
        System.assertEquals(
            new Set<String>(),
            extractedEntities('SELECT Id FROM 123 WHERE Name != NULL'),
            'A FROM target that cannot be an entity name should be ignored'
        );
    }

    @isTest
    static void testUnresolvableRelationshipIsSkipped() {
        System.assertEquals(
            new Set<String>{'account'},
            extractedEntities('SELECT Id, (SELECT Id FROM NotARelationship__r) FROM Account'),
            'An unresolvable relationship name should be skipped, keeping the real entity'
        );
    }

    @isTest
    static void testDefaultProviderMethodsCovered() {
        // Reset to the real provider so DefaultProvider methods are executed and covered
        TrxSec_DetectHighRiskBulkAPI.resetProviderForTest();

        List<String> levels = TrxSec_DetectHighRiskBulkAPI.provider.getHighRiskLevels();
        System.assertNotEquals(null, levels, 'High risk levels list should not be null');

        // Use a real EntityDefinition durable id to avoid assumptions about QueriedEntities format
        String accountEntityDefinitionId = [
            SELECT DurableId
            FROM EntityDefinition
            WHERE QualifiedApiName = 'Account'
            LIMIT 1
        ].DurableId;

        // Pass a non-empty classification list so the SOQL in getConfidentialFields executes
        List<String> fields = TrxSec_DetectHighRiskBulkAPI.provider.getConfidentialFields(
            accountEntityDefinitionId,
            new List<String>{'HIGH'}
        );
        System.assertNotEquals(null, fields, 'Confidential fields list should not be null');
    }
}
