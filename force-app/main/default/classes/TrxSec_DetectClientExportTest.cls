/**
 * @description Test class for TrxSec_DetectClientExport
 */
@isTest
private class TrxSec_DetectClientExportTest {

    private static ApiEvent buildEvent(String client, Integer rowsProcessed) {
        ApiEvent evt = new ApiEvent();
        evt.Client = client;
        evt.RowsProcessed = rowsProcessed;
        return evt;
    }

    @isTest
    static void testDetectsExportOverLimit() {
        System.assertEquals(true,
            new TrxSec_DetectClientExport().evaluate(buildEvent('Salesforce Inspector Reloaded', 2001)),
            'Export above the row limit should trigger');
    }

    @isTest
    static void testDetectsExportWithUnknownLargeRowCount() {
        System.assertEquals(true,
            new TrxSec_DetectClientExport().evaluate(buildEvent('Salesforce Inspector Reloaded', -1)),
            'A RowsProcessed of -1 means the batch size was exceeded and should trigger');
    }

    @isTest
    static void testAllowsExportAtOrBelowLimit() {
        TrxSec_DetectClientExport policy = new TrxSec_DetectClientExport();

        System.assertEquals(false, policy.evaluate(buildEvent('Salesforce Inspector Reloaded', 2000)), 'At the limit');
        System.assertEquals(false, policy.evaluate(buildEvent('Salesforce Inspector Reloaded', 10)), 'Below the limit');
    }

    @isTest
    static void testIgnoresUnmonitoredClients() {
        System.assertEquals(false,
            new TrxSec_DetectClientExport().evaluate(buildEvent('Data Loader', 50000)),
            'Clients that are not in the monitored list are out of scope');
    }

    @isTest
    static void testMonitorsEveryConfiguredClient() {
        TrxSec_DetectClientExport.monitoredClients = new Set<String>{ 'Data Loader', 'Workbench' };
        TrxSec_DetectClientExport policy = new TrxSec_DetectClientExport();

        System.assertEquals(true, policy.evaluate(buildEvent('Data Loader', 5000)), 'First configured client');
        System.assertEquals(true, policy.evaluate(buildEvent('workbench', 5000)), 'Second client, case insensitive');
        System.assertEquals(false, policy.evaluate(buildEvent('Salesforce Inspector Reloaded', 5000)),
            'The default client is no longer monitored once the list is replaced');
    }

    @isTest
    static void testEmptyClientListMonitorsNothing() {
        TrxSec_DetectClientExport.monitoredClients = new Set<String>();

        System.assertEquals(false,
            new TrxSec_DetectClientExport().evaluate(buildEvent('Salesforce Inspector Reloaded', 5000)),
            'An empty list must not trigger');
    }

    @isTest
    static void testConfiguredThresholdOverridesDefaultLimit() {
        TrxSec_ThresholdSettings.overridesForTest.put(
            TrxSec_ThresholdSettings.EVENT_CLIENT_EXPORT, new List<Integer>{ 100 }
        );
        TrxSec_DetectClientExport policy = new TrxSec_DetectClientExport();

        System.assertEquals(true, policy.evaluate(buildEvent('Salesforce Inspector Reloaded', 101)), 'Above configured limit');
        System.assertEquals(false, policy.evaluate(buildEvent('Salesforce Inspector Reloaded', 100)), 'At configured limit');
    }

    @isTest
    static void testHandlesBlankValues() {
        TrxSec_DetectClientExport policy = new TrxSec_DetectClientExport();

        System.assertEquals(false, policy.evaluate(buildEvent(null, 5000)), 'Blank client');
        System.assertEquals(false, policy.evaluate(buildEvent('Salesforce Inspector Reloaded', null)), 'Blank row count');
    }

    @isTest
    static void testHandlesNullAndUnsupportedEvent() {
        TrxSec_DetectClientExport policy = new TrxSec_DetectClientExport();

        System.assertEquals(false, policy.evaluate(null), 'Null event should not trigger');
        System.assertEquals(false, policy.evaluate(new PermissionSetEventStore()), 'Unhandled event type should not trigger');
    }

    @isTest
    static void testExcludedUserIsNeverFlagged() {
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = '005000000000001AAA',
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_CLIENT_EXPORT
            )
        };
        ApiEvent evt = buildEvent('Salesforce Inspector Reloaded', 5000);
        evt.UserId = '005000000000001AAA';

        System.assertEquals(false, new TrxSec_DetectClientExport().evaluate(evt), 'Excluded user should not trigger');
        evt.UserId = '005000000000002AAA';
        System.assertEquals(true, new TrxSec_DetectClientExport().evaluate(evt), 'Other users are still flagged');
    }
}
