/**
 * @description Test class for TrxSec_DetectLargeDataCloudQueries
 */
@isTest
private class TrxSec_DetectLargeDataCloudQueriesTest {

    private static ApiEvent buildEvent(String queriedEntities, Integer rowsProcessed) {
        ApiEvent evt = new ApiEvent();
        evt.QueriedEntities = queriedEntities;
        evt.RowsProcessed = rowsProcessed;
        return evt;
    }

    @isTest
    static void testDetectsLargeDataCloudQuery() {
        System.assertEquals(true,
            new TrxSec_DetectLargeDataCloudQueries().evaluate(buildEvent('UnifiedIndividual__dlm', 2001)),
            'More than 2,000 rows on a Data 360 object should trigger');
    }

    @isTest
    static void testDetectsUnknownLargeRowCount() {
        System.assertEquals(true,
            new TrxSec_DetectLargeDataCloudQueries().evaluate(buildEvent('Account,UnifiedIndividual__dlm', -1)),
            'A RowsProcessed of -1 should trigger when a Data 360 object is queried');
    }

    @isTest
    static void testDetectsOtherDataCloudSuffixes() {
        TrxSec_DetectLargeDataCloudQueries policy = new TrxSec_DetectLargeDataCloudQueries();

        for (String suffix : TrxSec_DetectLargeDataCloudQueries.dataCloudSuffixes) {
            System.assertEquals(true, policy.evaluate(buildEvent('Sample' + suffix, 5000)),
                'Suffix ' + suffix + ' should be treated as Data 360');
        }
    }

    @isTest
    static void testAllowsSmallDataCloudQuery() {
        TrxSec_DetectLargeDataCloudQueries policy = new TrxSec_DetectLargeDataCloudQueries();

        System.assertEquals(false, policy.evaluate(buildEvent('UnifiedIndividual__dlm', 2000)), 'At the limit');
        System.assertEquals(false, policy.evaluate(buildEvent('UnifiedIndividual__dlm', 25)), 'Below the limit');
    }

    @isTest
    static void testIgnoresStandardObjects() {
        System.assertEquals(false,
            new TrxSec_DetectLargeDataCloudQueries().evaluate(buildEvent('Account', 100000)),
            'Queries on non Data 360 objects are out of scope');
    }

    @isTest
    static void testHandlesBlankValues() {
        TrxSec_DetectLargeDataCloudQueries policy = new TrxSec_DetectLargeDataCloudQueries();

        System.assertEquals(false, policy.evaluate(buildEvent(null, 5000)), 'Blank queried entities');
        System.assertEquals(false, policy.evaluate(buildEvent('UnifiedIndividual__dlm', null)), 'Blank row count');
    }

    @isTest
    static void testHandlesNullAndUnsupportedEvent() {
        TrxSec_DetectLargeDataCloudQueries policy = new TrxSec_DetectLargeDataCloudQueries();

        System.assertEquals(false, policy.evaluate(null), 'Null event should not trigger');
        System.assertEquals(false, policy.evaluate(new PermissionSetEventStore()), 'Unhandled event type should not trigger');
    }

    @isTest
    static void testConfiguredThresholdOverridesDefaultLimit() {
        TrxSec_ThresholdSettings.overridesForTest.put(
            TrxSec_ThresholdSettings.EVENT_DATA_CLOUD_QUERY, new List<Integer>{ 100 }
        );
        TrxSec_DetectLargeDataCloudQueries policy = new TrxSec_DetectLargeDataCloudQueries();

        System.assertEquals(true, policy.evaluate(buildEvent('UnifiedIndividual__dlm', 101)), 'Above configured limit');
        System.assertEquals(false, policy.evaluate(buildEvent('UnifiedIndividual__dlm', 100)), 'At configured limit');
    }

    @isTest
    static void testSuffixesAreCustomizable() {
        TrxSec_DetectLargeDataCloudQueries.dataCloudSuffixes = new Set<String>{ '__custom' };
        TrxSec_DetectLargeDataCloudQueries policy = new TrxSec_DetectLargeDataCloudQueries();

        System.assertEquals(true, policy.evaluate(buildEvent('Thing__CUSTOM', 5000)), 'Configured suffix, case insensitive');
        System.assertEquals(false, policy.evaluate(buildEvent('UnifiedIndividual__dlm', 5000)), 'Default suffix no longer matches');
    }

    @isTest
    static void testExcludedUserIsNeverFlagged() {
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = '005000000000001AAA',
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_LARGE_DATA_CLOUD_QUERIES
            )
        };
        ApiEvent evt = buildEvent('UnifiedIndividual__dlm', 5000);
        evt.UserId = '005000000000001AAA';

        System.assertEquals(false, new TrxSec_DetectLargeDataCloudQueries().evaluate(evt), 'Excluded user should not trigger');
        evt.UserId = '005000000000002AAA';
        System.assertEquals(true, new TrxSec_DetectLargeDataCloudQueries().evaluate(evt), 'Other users are still flagged');
    }
}
