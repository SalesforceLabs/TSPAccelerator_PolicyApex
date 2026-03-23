/**
 * @description Transaction Security Policy condition to detect anomalous behavior from guest users
 */
global with sharing class TrxSec_DetectGuestUserAnomaly implements TxnSecurity.EventCondition {
    
    global boolean evaluate(SObject event) {
        switch on event{
            when GuestUserAnomalyEventStore guestUserAnomalyEventStore {
                return evaluate(guestUserAnomalyEventStore);
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
    private boolean evaluate(GuestUserAnomalyEventStore guestUserAnomalyEventStore) {
        return true;
    }
}