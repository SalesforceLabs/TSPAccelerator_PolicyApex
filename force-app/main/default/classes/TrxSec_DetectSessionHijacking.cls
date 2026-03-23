/**
 * @description Transaction Security Policy condition to detect session hijacking attempts
 */
global with sharing class TrxSec_DetectSessionHijacking implements TxnSecurity.EventCondition {
    
    global Boolean evaluate(SObject event) {
        switch on event{
            when SessionHijackingEventStore sessionHijackingEventStore {
                return evaluate(sessionHijackingEventStore);
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
    private boolean evaluate(SessionHijackingEventStore sessionHijackingEventStore) {
        return true;
    }
}