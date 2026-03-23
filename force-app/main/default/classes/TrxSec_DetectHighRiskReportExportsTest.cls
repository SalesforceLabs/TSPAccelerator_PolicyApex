/**
 * @description Test class for TrxSec_DetectHighRiskReportExports
 */
@isTest
private class TrxSec_DetectHighRiskReportExportsTest {
    private class StubProvider implements TrxSec_DetectHighRiskReportExports.Provider {
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
        TrxSec_DetectHighRiskReportExports.provider = new StubProvider(highRiskLevels, confidentialFields);
    }

    @isTest
    static void testReturnsFalseWhenNoHighRiskLevelsConfigured() {
        useProvider(new List<String>(), new List<String>());

        ReportEvent testEvent = new ReportEvent();
        testEvent.Operation = 'ReportExported';
        testEvent.QueriedEntities = 'Contact';
        testEvent.ColumnHeaders = 'FirstName,LastName';

        Boolean result = new TrxSec_DetectHighRiskReportExports().evaluate(testEvent);
        System.assertEquals(false, result, 'Should allow when no high-risk levels are configured');
    }

    @isTest
    static void testNonExportOperationReturnsFalse() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ReportEvent testEvent = new ReportEvent();
        testEvent.Operation = 'ReportPreviewed';
        testEvent.QueriedEntities = 'Contact';
        testEvent.ColumnHeaders = 'SSN__c';

        Boolean result = new TrxSec_DetectHighRiskReportExports().evaluate(testEvent);
        System.assertEquals(false, result, 'Non-export operations should be allowed');
    }

    @isTest
    static void testNullOperationReturnsFalse() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ReportEvent testEvent = new ReportEvent();
        testEvent.Operation = null;
        testEvent.QueriedEntities = 'Contact';
        testEvent.ColumnHeaders = 'SSN__c';

        Boolean result = new TrxSec_DetectHighRiskReportExports().evaluate(testEvent);
        System.assertEquals(false, result, 'Null operation should return false');
    }

    @isTest
    static void testEmptyInputsReturnFalse() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ReportEvent emptyEntities = new ReportEvent();
        emptyEntities.Operation = 'ReportExported';
        emptyEntities.QueriedEntities = '';
        emptyEntities.ColumnHeaders = 'SSN__c';
        System.assertEquals(false, new TrxSec_DetectHighRiskReportExports().evaluate(emptyEntities), 'Empty entities should return false');

        ReportEvent emptyColumns = new ReportEvent();
        emptyColumns.Operation = 'ReportExported';
        emptyColumns.QueriedEntities = 'Contact';
        emptyColumns.ColumnHeaders = '';
        System.assertEquals(false, new TrxSec_DetectHighRiskReportExports().evaluate(emptyColumns), 'Empty column headers should return false');
    }

    @isTest
    static void testDetectsConfidentialFieldOnExport() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ReportEvent testEvent = new ReportEvent();
        testEvent.Operation = 'ReportExportedToExcel';
        testEvent.QueriedEntities = 'Contact';
        testEvent.ColumnHeaders = 'FirstName,LastName,SSN__c';

        Boolean result = new TrxSec_DetectHighRiskReportExports().evaluate(testEvent);
        System.assertEquals(true, result, 'Should detect confidential field in ColumnHeaders on export');
    }

    @isTest
    static void testDoesNotDetectWhenFieldNotPresent() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ReportEvent testEvent = new ReportEvent();
        testEvent.Operation = 'ReportExported';
        testEvent.QueriedEntities = 'Contact';
        testEvent.ColumnHeaders = 'FirstName,LastName';

        Boolean result = new TrxSec_DetectHighRiskReportExports().evaluate(testEvent);
        System.assertEquals(false, result, 'Should not detect when field is not present');
    }

    @isTest
    static void testDefaultProviderMethodsCovered() {
        // Reset to the real provider so DefaultProvider methods are executed and covered
        TrxSec_DetectHighRiskReportExports.resetProviderForTest();

        List<String> levels = TrxSec_DetectHighRiskReportExports.provider.getHighRiskLevels();
        System.assertNotEquals(null, levels, 'High risk levels list should not be null');

        String accountEntityDefinitionId = [
            SELECT DurableId
            FROM EntityDefinition
            WHERE QualifiedApiName = 'Account'
            LIMIT 1
        ].DurableId;

        List<String> fields = TrxSec_DetectHighRiskReportExports.provider.getConfidentialFields(
            accountEntityDefinitionId,
            new List<String>{'HIGH'}
        );
        System.assertNotEquals(null, fields, 'Confidential fields list should not be null');
    }
}

