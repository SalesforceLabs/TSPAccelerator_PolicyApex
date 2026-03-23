/**
 * @description Transaction Security Policy condition to detect privilege escalation through permission sets
 */
global with sharing class TrxSec_DetectPrivilegeEscalation implements TxnSecurity.EventCondition {
    
    global Boolean evaluate(SObject event) {
        switch on event{
            when PermissionSetEventStore permissionSetEventStore {
                return evaluate(permissionSetEventStore);
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
    private boolean evaluate(PermissionSetEventStore permissionSetEventStore) {
        return true;
    }
}