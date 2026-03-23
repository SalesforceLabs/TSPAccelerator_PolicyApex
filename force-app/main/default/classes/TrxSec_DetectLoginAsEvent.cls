/**
 * @description Transaction Security Policy condition to detect Login As events
 */
global with sharing class TrxSec_DetectLoginAsEvent implements TxnSecurity.EventCondition {
    /***********************************************************
    * DETECT LOGIN AS EVENTS.
    * LoginAsEvent is triggered when an administrator logs in as another user.
    * This policy detects all Login As events for monitoring and security purposes.
    ***********************************************************/

    global boolean evaluate(SObject event){
        // Simply return true to trigger on all LoginAsEvent occurrences
        return true;
    }
}
