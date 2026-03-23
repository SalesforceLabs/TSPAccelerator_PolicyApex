/**
 * @description Transaction Security Policy condition to detect standard users logging in without SSO
 */
global with sharing class TrxSec_DetectNonSSOLogins implements TxnSecurity.EventCondition {
    
    global Boolean evaluate(SObject event) {
        switch on event {
            when LoginEvent loginEvent {
                return evaluate(loginEvent);
            }
            when else {
                return false;
            }
        }
    }
    
    private Boolean evaluate(LoginEvent loginEvent) {
        // Return true if LoginType is 'Application' and UserType is 'Standard'
        // This indicates a non-SSO login that should be flagged
        return 'Application'.equals(loginEvent.LoginType) 
            && 'Standard'.equals(loginEvent.UserType);
    }
}