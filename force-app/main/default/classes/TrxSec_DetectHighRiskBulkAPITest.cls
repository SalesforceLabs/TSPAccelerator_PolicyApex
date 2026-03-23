/**
 * @description Test class for TrxSec_DetectHighRiskBulkAPI
 */
@isTest
private class TrxSec_DetectHighRiskBulkAPITest {
    private class StubProvider implements TrxSec_DetectHighRiskBulkAPI.Provider {
        private final List<String> highRiskLevels;
        private final List<String> confidentialFields;

        StubProvider(List<String> highRiskLevels, List<String> confidentialFields) {
            this.highRiskLevels = highRiskLevels;
            this.confidentialFields = confidentialFields;
        }

        public List<String> getHighRiskLevels() {
            return highRiskLevels == null ? new List<String>() : highRiskLevels;
        }

        public List<String> getConfidentialFields(String entity, List<String> ignoredHighRiskLevels) {
            return confidentialFields == null ? new List<String>() : confidentialFields;
        }
    }

    private static void useProvider(List<String> highRiskLevels, List<String> confidentialFields) {
        TrxSec_DetectHighRiskBulkAPI.provider = new StubProvider(highRiskLevels, confidentialFields);
    }

    @isTest
    static void testReturnsFalseWhenNoHighRiskLevelsConfigured() {
        useProvider(new List<String>(), new List<String>());

        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = 'SELECT Id, Name FROM Account';

        Boolean result = new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
        System.assertEquals(false, result, 'Should allow when no high-risk levels are configured');
    }

    @isTest
    static void testNullQueryHandled() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = null;

        Boolean result = new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
        System.assertEquals(false, result, 'Null Query should be handled safely');
    }

    @isTest
    static void testEmptyQueryHandled() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = '';

        Boolean result = new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
        System.assertEquals(false, result, 'Empty Query should be handled safely');
    }

    @isTest
    static void testDetectsConfidentialFieldInQuery() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = 'SELECT Id, SSN__c FROM Account';

        Boolean result = new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
        System.assertEquals(true, result, 'Should detect confidential field in query');
    }

    @isTest
    static void testDoesNotDetectWhenFieldNotPresent() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = 'SELECT Id, Name FROM Account';

        Boolean result = new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
        System.assertEquals(false, result, 'Should not detect when field is not present');
    }

    @isTest
    static void testQueryWithWhereClause() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = 'SELECT Id, SSN__c FROM Account WHERE CreatedDate > TODAY';

        Boolean result = new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
        System.assertEquals(true, result, 'Should detect confidential field in query with WHERE clause');
    }

    @isTest
    static void testQueryWithoutFromClause() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        BulkApiResultEventStore testEvent = new BulkApiResultEventStore();
        testEvent.Query = 'SELECT Id, Name';

        Boolean result = new TrxSec_DetectHighRiskBulkAPI().evaluate(testEvent);
        System.assertEquals(false, result, 'Should handle query without FROM clause');
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
