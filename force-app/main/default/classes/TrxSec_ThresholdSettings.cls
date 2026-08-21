/**
 * @description Resolves subscriber-configurable record-count thresholds for the Total Access
 * detection policies. Backed by Detection_Threshold__mdt records, each tied to a specific
 * Real-Time Event through the Event_Name__c picklist. If a subscriber adds more than one
 * record for the same event, the lowest threshold wins so an added record can only tighten
 * the policy, never loosen it.
 *
 * A hard-coded DEFAULT_THRESHOLD is used whenever no usable record exists for the event, so
 * a deleted, blank, or non-positive value can never turn the policy into "fire on every
 * event". getAll() on a custom metadata type is free of SOQL, which matters because this is
 * invoked from a metered TxnSecurity.EventCondition.
 */
public with sharing class TrxSec_ThresholdSettings {

    public static final Integer DEFAULT_THRESHOLD = 10000;

    // Picklist API values on Detection_Threshold__mdt.Event_Name__c, kept as constants so
    // policy classes never string-literal an event name at the call site.
    public static final String EVENT_API = 'ApiEvent';
    public static final String EVENT_LIST_VIEW = 'ListViewEvent';
    public static final String EVENT_REPORT = 'ReportEvent';

    // Custom metadata records cannot be created or modified via DML, so tests need another
    // way to exercise the resolver. Each key is an event name and the value is the list of
    // Threshold__c values that would come out of Detection_Threshold__mdt.getAll() for that
    // event, so tests can drive both the single-record and multi-record min paths. The same
    // null / zero / negative rules that apply to CMDT records apply here.
    @TestVisible
    private static Map<String, List<Integer>> overridesForTest = new Map<String, List<Integer>>();

    /**
     * @description Returns the lowest positive Threshold__c value across every
     * Detection_Threshold__mdt record whose Event_Name__c matches the given event, or
     * DEFAULT_THRESHOLD when no usable record exists or the lookup throws. Never returns
     * null and never lets an exception escape, because an exception thrown from inside a
     * TSP condition has unpredictable enforcement consequences.
     *
     * @param eventName One of the EVENT_* constants (or any Event_Name__c picklist API value).
     */
    public static Integer getThreshold(String eventName) {
        Integer lowest = null;

        if (overridesForTest.containsKey(eventName)) {
            for (Integer candidate : overridesForTest.get(eventName)) {
                lowest = minPositive(lowest, candidate);
            }
        } else {
            try {
                for (Detection_Threshold__mdt setting : Detection_Threshold__mdt.getAll().values()) {
                    if (setting.Event_Name__c != eventName || setting.Threshold__c == null) {
                        continue;
                    }
                    lowest = minPositive(lowest, Integer.valueOf(setting.Threshold__c));
                }
            } catch (Exception ex) {
                // Any failure resolving the value silently uses the default rather than
                // propagating out of a TSP condition.
                System.debug(LoggingLevel.WARN, 'TrxSec_ThresholdSettings.getThreshold: falling back to default for ' + eventName + ' due to ' + ex.getTypeName());
            }
        }

        return lowest == null ? DEFAULT_THRESHOLD : lowest;
    }

    /**
     * Returns the smaller of currentMin and candidate, treating null or non-positive
     * candidates as absent. Kept private because the "positive only" filter is specific to
     * threshold semantics.
     */
    private static Integer minPositive(Integer currentMin, Integer candidate) {
        if (candidate == null || candidate <= 0) {
            return currentMin;
        }
        if (currentMin == null || candidate < currentMin) {
            return candidate;
        }
        return currentMin;
    }
}
