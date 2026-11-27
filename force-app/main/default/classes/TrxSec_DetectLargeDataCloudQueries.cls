/**
 * @description Transaction Security Policy condition to detect API queries on Data 360 (Data Cloud)
 * objects returning more than 2,000 rows. Intended for ApiEvent, for example to limit the volume
 * a companion org user can query.
 *
 * ApiEvent.RowsProcessed is reported as -1 once the row count exceeds the API batch size, so a
 * precise threshold above 2,000 cannot be expressed. Volume can be tuned through the number of
 * threads used by the client. The 2,000 default can be lowered through TrxSec_ThresholdSettings.
 */
global with sharing class TrxSec_DetectLargeDataCloudQueries implements TxnSecurity.EventCondition {

    // Suffixes of Data 360 objects matched against ApiEvent.QueriedEntities, case-insensitively:
    // __dlm (data model object, from the reference policy), __dll (data lake object) and __cio
    // (calculated insight). Add other suffixes to extend the policy.
    @TestVisible
    private static Set<String> dataCloudSuffixes = new Set<String>{ '__dlm', '__dll', '__cio' };

    // Default row limit, overridable through TrxSec_ThresholdSettings (key EVENT_DATA_CLOUD_QUERY).
    @TestVisible
    private static final Integer DEFAULT_ROW_LIMIT = 2000;

    @TestVisible
    private static final Integer ROWS_UNKNOWN_LARGE = -1;

    global Boolean evaluate(SObject event) {
        switch on event {
            when ApiEvent apiEvent {
                return isViolation(apiEvent);
            }
            when null {
                // Don't take policy action when event is null
                return false;
            }
            when else {
                // Don't take policy action when event is not handled
                return false;
            }
        }
    }

    private Boolean isViolation(ApiEvent apiEvent) {
        // Subscriber-configured exclusions are honored first, so an excluded user can never trip this policy.
        if (TrxSec_PolicyExclusions.isExcluded(TrxSec_PolicyExclusions.POLICY_LARGE_DATA_CLOUD_QUERIES, apiEvent.UserId)) {
            return false;
        }
        if (apiEvent.RowsProcessed == null || !queriesDataCloud(apiEvent.QueriedEntities)) {
            return false;
        }
        Integer rowLimit = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_DATA_CLOUD_QUERY, DEFAULT_ROW_LIMIT
        );
        return apiEvent.RowsProcessed > rowLimit || apiEvent.RowsProcessed == ROWS_UNKNOWN_LARGE;
    }

    private Boolean queriesDataCloud(String queriedEntities) {
        if (String.isBlank(queriedEntities)) {
            return false;
        }
        for (String suffix : dataCloudSuffixes) {
            if (queriedEntities.containsIgnoreCase(suffix)) {
                return true;
            }
        }
        return false;
    }
}
