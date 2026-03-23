/**
 * @description Transaction Security Policy condition to detect credential stuffing attacks
 */
global with sharing class TrxSec_DetectCredentialStuffing implements TxnSecurity.EventCondition {
    
    global boolean evaluate(SObject event) {
        switch on event{
            when CredentialStuffingEventStore credentialStuffingEventStore {
                return evaluate(credentialStuffingEventStore);
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
    private boolean evaluate(CredentialStuffingEventStore credentialStuffingEventStore) {
        return true;
    }
}