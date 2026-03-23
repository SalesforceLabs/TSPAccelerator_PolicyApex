/**
 * @description Transaction Security Policy condition to detect anomalous login patterns
 */
global with sharing class TrxSec_DetectLoginAnomaly implements TxnSecurity.EventCondition {
    
    global Boolean evaluate(SObject event) {
        switch on event{
            when LoginAnomalyEventStore loginAnomalyEventStore {
                return evaluate(loginAnomalyEventStore);
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
    private boolean evaluate(LoginAnomalyEventStore loginAnomalyEventStore) {
        return true;
    }
}