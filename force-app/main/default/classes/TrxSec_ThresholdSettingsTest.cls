/**
 * @description Tests for TrxSec_ThresholdSettings. Custom metadata records cannot be inserted
 * via DML, so tests exercise the resolution rules through the overridesForTest hook and
 * verify the packaged 10,000 default is returned for each shipped event association.
 */
@IsTest
private class TrxSec_ThresholdSettingsTest {

    @IsTest
    static void returnsPackagedDefaultForShippedEvents() {
        Test.startTest();
        Integer apiThreshold = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_API
        );
        Integer listViewThreshold = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_LIST_VIEW
        );
        Integer reportThreshold = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_REPORT
        );
        Test.stopTest();

        System.assertEquals(10000, apiThreshold, 'Packaged ApiEvent record ships at 10,000');
        System.assertEquals(10000, listViewThreshold, 'Packaged ListViewEvent record ships at 10,000');
        System.assertEquals(10000, reportThreshold, 'Packaged ReportEvent record ships at 10,000');
    }

    @IsTest
    static void singleOverrideShortCircuitsLookup() {
        TrxSec_ThresholdSettings.overridesForTest.put(
            TrxSec_ThresholdSettings.EVENT_API, new List<Integer>{ 250 }
        );

        Test.startTest();
        Integer result = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_API
        );
        Test.stopTest();

        System.assertEquals(250, result, 'A single override value must be returned as the resolved threshold');
    }

    /**
     * Core semantic of the feature: when multiple records target the same event, the lowest
     * positive value wins so an added record can only tighten the policy, never loosen it.
     */
    @IsTest
    static void multipleOverridesReturnLowestPositive() {
        TrxSec_ThresholdSettings.overridesForTest.put(
            TrxSec_ThresholdSettings.EVENT_API, new List<Integer>{ 800, 200, 500 }
        );

        Test.startTest();
        Integer result = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_API
        );
        Test.stopTest();

        System.assertEquals(200, result, 'The lowest positive value across records must win');
    }

    /**
     * Non-positive and null entries do not participate in the min selection, but must not
     * cause the whole event to fall back to the default when at least one positive record
     * exists.
     */
    @IsTest
    static void nullZeroAndNegativeEntriesAreIgnoredInMin() {
        TrxSec_ThresholdSettings.overridesForTest.put(
            TrxSec_ThresholdSettings.EVENT_API,
            new List<Integer>{ null, 0, -100, 750, 900 }
        );

        Test.startTest();
        Integer result = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_API
        );
        Test.stopTest();

        System.assertEquals(
            750,
            result,
            'Null, zero and negative entries must be ignored so a bad record cannot bypass ' +
                'or accidentally disable the policy while other records exist'
        );
    }

    @IsTest
    static void unknownEventFallsBackToDefault() {
        Test.startTest();
        Integer result = TrxSec_ThresholdSettings.getThreshold('NoSuchEvent');
        Test.stopTest();

        System.assertEquals(
            TrxSec_ThresholdSettings.DEFAULT_THRESHOLD,
            result,
            'Unknown event with no matching records must fall back to the hard-coded default'
        );
    }

    @IsTest
    static void allNonPositiveOverridesFallBackToDefault() {
        TrxSec_ThresholdSettings.overridesForTest.put(
            TrxSec_ThresholdSettings.EVENT_API,
            new List<Integer>{ null, 0, -50 }
        );

        Test.startTest();
        Integer result = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_API
        );
        Test.stopTest();

        System.assertEquals(
            TrxSec_ThresholdSettings.DEFAULT_THRESHOLD,
            result,
            'When every candidate is null, zero or negative the default must apply so the ' +
                'policy never becomes a no-op or a fire-on-every-event'
        );
    }

    @IsTest
    static void emptyOverrideListFallsBackToDefault() {
        TrxSec_ThresholdSettings.overridesForTest.put(
            TrxSec_ThresholdSettings.EVENT_API, new List<Integer>()
        );

        Test.startTest();
        Integer result = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_API
        );
        Test.stopTest();

        System.assertEquals(
            TrxSec_ThresholdSettings.DEFAULT_THRESHOLD,
            result,
            'An empty candidate list is the "no records for this event" case'
        );
    }
}
