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

    /**
     * Exercises every export value the ReportEvent.Operation restricted picklist actually defines.
     * This previously asserted on 'ReportExportedToExcel', a value the platform never emits: a UI
     * export to Excel reports Operation='ReportExported' and carries the format in the separate
     * ExportFileFormat field, so that assertion passed for the wrong reason and gave false
     * confidence that the non-plain export paths were covered.
     */
    @isTest
    static void testDetectsConfidentialFieldOnEveryExportOperation() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        List<String> exportOperations = new List<String>{
            'ReportExported',
            'ReportExportedAsynchronously',
            'ReportExportedUsingExcelConnector'
        };

        for (String exportOperation : exportOperations) {
            ReportEvent testEvent = new ReportEvent();
            testEvent.Operation = exportOperation;
            testEvent.QueriedEntities = 'Contact';
            testEvent.ColumnHeaders = 'FirstName,LastName,SSN__c';

            Boolean result = new TrxSec_DetectHighRiskReportExports().evaluate(testEvent);
            System.assertEquals(true, result,
                'Should detect confidential field in ColumnHeaders on export. Operation: ' + exportOperation);
        }
    }

    /**
     * A UI export to Excel emits Operation='ReportExported'; the file format is carried separately
     * in ExportFileFormat and must not influence the guard.
     */
    @isTest
    static void testExportFileFormatDoesNotAffectGuard() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        for (String fileFormat : new List<String>{ 'CSV', 'Excel' }) {
            ReportEvent testEvent = new ReportEvent();
            testEvent.Operation = 'ReportExported';
            testEvent.ExportFileFormat = fileFormat;
            testEvent.QueriedEntities = 'Contact';
            testEvent.ColumnHeaders = 'FirstName,LastName,SSN__c';

            System.assertEquals(true, new TrxSec_DetectHighRiskReportExports().evaluate(testEvent),
                'ExportFileFormat must not change the export decision. Format: ' + fileFormat);
        }
    }

    /**
     * A real non-export Operation picklist value must return false. 'ReportRunFromLightning' is
     * used rather than an invented value, so this genuinely exercises the guard.
     */
    @isTest
    static void testRealNonExportOperationReturnsFalse() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        ReportEvent testEvent = new ReportEvent();
        testEvent.Operation = 'ReportRunFromLightning';
        testEvent.QueriedEntities = 'Contact';
        testEvent.ColumnHeaders = 'SSN__c';

        System.assertEquals(false, new TrxSec_DetectHighRiskReportExports().evaluate(testEvent),
            'ReportRunFromLightning is not an export and must return false');
    }

    /**
     * Operation is nillable, so blank input must return false without throwing. An exception
     * escaping a TSP condition has unpredictable enforcement consequences.
     */
    @isTest
    static void testBlankOperationReturnsFalseWithoutException() {
        useProvider(new List<String>{'HIGH'}, new List<String>{'ssn__c'});

        for (String blankOperation : new List<String>{ null, '' }) {
            ReportEvent testEvent = new ReportEvent();
            testEvent.Operation = blankOperation;
            testEvent.QueriedEntities = 'Contact';
            testEvent.ColumnHeaders = 'SSN__c';

            try {
                System.assertEquals(false, new TrxSec_DetectHighRiskReportExports().evaluate(testEvent),
                    'A blank Operation must return false. Operation: ' + blankOperation);
            } catch (Exception e) {
                System.assert(false,
                    'A blank Operation must not throw out of evaluate(). Operation: ' +
                        blankOperation + ', exception: ' + e.getTypeName() + ' - ' + e.getMessage());
            }
        }
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

