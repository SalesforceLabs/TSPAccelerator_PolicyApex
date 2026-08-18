/**
 * @description Test class for TrxSec_ReportEventUtils
 */
@isTest
private class TrxSec_ReportEventUtilsTest {

    /**
     * Every export value defined by the ReportEvent.Operation restricted picklist must be
     * recognised. Matching only 'ReportExported' is the defect these three cases lock down.
     */
    @isTest
    static void testAllExportOperationsAreRecognised() {
        List<String> exportOperations = new List<String>{
            'ReportExported',
            'ReportExportedAsynchronously',
            'ReportExportedUsingExcelConnector'
        };

        for (String exportOperation : exportOperations) {
            System.assertEquals(true, TrxSec_ReportEventUtils.isReportExportOperation(exportOperation),
                'Should be recognised as an export. Operation: ' + exportOperation);
        }
    }

    /**
     * Real non-export values from the same picklist must not be treated as exports. These are
     * actual picklist values rather than invented strings, so they genuinely exercise the guard.
     */
    @isTest
    static void testNonExportOperationsAreRejected() {
        List<String> nonExportOperations = new List<String>{
            'ReportRunFromLightning',
            'ReportRunFromClassic',
            'ReportPreviewed',
            'ReportScheduled',
            'ReportRunUsingAsynchronousApi',
            'DashboardComponentUpdated',
            'Unknown'
        };

        for (String nonExportOperation : nonExportOperations) {
            System.assertEquals(false, TrxSec_ReportEventUtils.isReportExportOperation(nonExportOperation),
                'Should not be recognised as an export. Operation: ' + nonExportOperation);
        }
    }

    /**
     * Operation is nillable, so blank input must return false rather than throwing. A prefix match
     * on a null value would raise a NullPointerException, and an exception escaping a TSP condition
     * has unpredictable enforcement consequences.
     */
    @isTest
    static void testBlankOperationReturnsFalseWithoutException() {
        for (String blankOperation : new List<String>{ null, '', '   ' }) {
            try {
                System.assertEquals(false, TrxSec_ReportEventUtils.isReportExportOperation(blankOperation),
                    'A blank operation is not an export. Operation: ' + blankOperation);
            } catch (Exception e) {
                System.assert(false,
                    'A blank operation must not throw. Operation: ' + blankOperation +
                        ', exception: ' + e.getTypeName() + ' - ' + e.getMessage());
            }
        }
    }

    /**
     * Picklist values are emitted in a fixed casing, and the previous exact-equality guard was
     * case sensitive. Prefix matching must stay case sensitive so that behaviour is preserved.
     */
    @isTest
    static void testMatchingIsCaseSensitive() {
        System.assertEquals(false, TrxSec_ReportEventUtils.isReportExportOperation('reportexported'),
            'Lowercase should not match');
        System.assertEquals(false, TrxSec_ReportEventUtils.isReportExportOperation('REPORTEXPORTED'),
            'Uppercase should not match');
    }

    /**
     * The point of prefix matching over an allowlist: an export value added by a future Salesforce
     * release is evaluated rather than silently ignored. This value does not exist today and is a
     * stand-in for whatever Salesforce adds next.
     */
    @isTest
    static void testFutureExportValueFailsTowardEvaluation() {
        System.assertEquals(true, TrxSec_ReportEventUtils.isReportExportOperation('ReportExportedSomeFutureWay'),
            'An unrecognised ReportExported* value must be evaluated, not ignored');
    }
}
