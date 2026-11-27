/**
 * @description Transaction Security Policy condition to detect large data exports made through
 * specific API clients (for example the Salesforce Inspector Reloaded browser extension).
 * Intended as a blocking policy on ApiEvent.
 *
 * The monitored client names live in monitoredClients. A user with a Policy_Exclusion__mdt record
 * for this policy is never flagged. The
 * row limit is resolved through TrxSec_ThresholdSettings (key EVENT_CLIENT_EXPORT) and defaults
 * to 2,000. ApiEvent.RowsProcessed is -1 once the row count exceeds the API batch size, which
 * is always treated as above the limit.
 */
global with sharing class TrxSec_DetectClientExport implements TxnSecurity.EventCondition {

    @TestVisible
    private static final Integer DEFAULT_ROW_LIMIT = 2000;

    @TestVisible
    private static final Integer ROWS_UNKNOWN_LARGE = -1;

    // Client names (ApiEvent.Client) to monitor, compared case-insensitively. Add the names of
    // other clients to extend the policy.
    @TestVisible
    private static Set<String> monitoredClients = new Set<String>{ 'Salesforce Inspector Reloaded' };

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
        if (TrxSec_PolicyExclusions.isExcluded(TrxSec_PolicyExclusions.POLICY_CLIENT_EXPORT, apiEvent.UserId)) {
            return false;
        }
        if (apiEvent.RowsProcessed == null || !isMonitoredClient(apiEvent.Client)) {
            return false;
        }
        Integer rowLimit = TrxSec_ThresholdSettings.getThreshold(
            TrxSec_ThresholdSettings.EVENT_CLIENT_EXPORT, DEFAULT_ROW_LIMIT
        );
        return apiEvent.RowsProcessed > rowLimit || apiEvent.RowsProcessed == ROWS_UNKNOWN_LARGE;
    }

    private Boolean isMonitoredClient(String client) {
        if (String.isBlank(client)) {
            return false;
        }
        for (String monitored : monitoredClients) {
            if (String.isNotBlank(monitored) && monitored.equalsIgnoreCase(client)) {
                return true;
            }
        }
        return false;
    }
}
