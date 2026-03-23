/**
 * @description Transaction Security Policy condition to detect anomalous API usage patterns
 */
global with sharing class TrxSec_DetectAPIAnomaly implements TxnSecurity.EventCondition {
    
    global boolean evaluate(SObject event) {
        switch on event{
            when ApiAnomalyEventStore apiAnomalyEventStore {
                return evaluate(apiAnomalyEventStore);
            }
            when null {
                // Don't take policy action when event is null
                return false;
            }
            when else{
                // Don't take policy action when event is not handled
                return false;
            }
        }
    }
    private boolean evaluate(ApiAnomalyEventStore apiAnomalyEventStore) {
        return true;
    }
}