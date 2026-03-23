/**
 * @description Test class for TrxSec_DetectHighRiskListView
 */
@isTest
private class TrxSec_DetectHighRiskListViewTest {
    private class StubProvider implements TrxSec_DetectHighRiskListView.Provider {
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
        TrxSec_DetectHighRiskListView.provider = new StubProvider(highRiskLevels, confidentialFields);
    }

    @isTest
    static void testReturnsFalseWhenNoHighRiskLevelsConfigured() {
        useProvider(new List<String>(), new List<String>());

        ListViewEvent testEvent = new ListViewEvent();
        testEvent.QueriedEntities = 'Account';
        testEvent.ColumnHeaders = 'Id,Name';

        Boolean result = new TrxSec_DetectHighRiskListView().evaluate(testEvent);
        System.assertEquals(false, result, 'Should allow when no high-risk levels are configured');
    }

    @isTest
    static void testNullQueriedEntitiesHandled() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ListViewEvent testEvent = new ListViewEvent();
        testEvent.QueriedEntities = null;
        testEvent.ColumnHeaders = 'Id,Name';

        Boolean result = new TrxSec_DetectHighRiskListView().evaluate(testEvent);
        System.assertEquals(false, result, 'Null QueriedEntities should be handled safely');
    }

    @isTest
    static void testNullColumnHeadersHandled() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ListViewEvent testEvent = new ListViewEvent();
        testEvent.QueriedEntities = 'Account';
        testEvent.ColumnHeaders = null;

        Boolean result = new TrxSec_DetectHighRiskListView().evaluate(testEvent);
        System.assertEquals(false, result, 'Null ColumnHeaders should be handled safely');
    }

    @isTest
    static void testDetectsConfidentialFieldInColumnHeaders() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ListViewEvent testEvent = new ListViewEvent();
        testEvent.QueriedEntities = 'Account';
        testEvent.ColumnHeaders = 'Id,Name,SSN__c';

        Boolean result = new TrxSec_DetectHighRiskListView().evaluate(testEvent);
        System.assertEquals(true, result, 'Should detect confidential field in ColumnHeaders');
    }

    @isTest
    static void testDoesNotDetectWhenFieldNotPresent() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ListViewEvent testEvent = new ListViewEvent();
        testEvent.QueriedEntities = 'Account';
        testEvent.ColumnHeaders = 'Id,Name';

        Boolean result = new TrxSec_DetectHighRiskListView().evaluate(testEvent);
        System.assertEquals(false, result, 'Should not detect when field is not present');
    }

    @isTest
    static void testMultipleEntitiesEvaluated() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ListViewEvent testEvent = new ListViewEvent();
        testEvent.QueriedEntities = 'Account,Contact';
        testEvent.ColumnHeaders = 'Id,Name,SSN__c';

        Boolean result = new TrxSec_DetectHighRiskListView().evaluate(testEvent);
        System.assertEquals(true, result, 'Should evaluate multiple entities and detect confidential fields');
    }

    @isTest
    static void testDefaultProviderMethodsCovered() {
        // Reset to the real provider so DefaultProvider methods are executed and covered
        TrxSec_DetectHighRiskListView.resetProviderForTest();

        List<String> levels = TrxSec_DetectHighRiskListView.provider.getHighRiskLevels();
        System.assertNotEquals(null, levels, 'High risk levels list should not be null');

        String accountEntityDefinitionId = [
            SELECT DurableId
            FROM EntityDefinition
            WHERE QualifiedApiName = 'Account'
            LIMIT 1
        ].DurableId;

        List<String> fields = TrxSec_DetectHighRiskListView.provider.getConfidentialFields(
            accountEntityDefinitionId,
            new List<String>{'HIGH'}
        );
        System.assertNotEquals(null, fields, 'Confidential fields list should not be null');
    }
}

