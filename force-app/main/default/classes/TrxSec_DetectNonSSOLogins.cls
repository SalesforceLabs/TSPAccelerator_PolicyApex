/**
 * @description Transaction Security Policy condition to detect standard users logging in without SSO
 */
global with sharing class TrxSec_DetectNonSSOLogins implements TxnSecurity.EventCondition {

    // Interactive UI login types that authenticate an internal user directly, bypassing SSO.
    // Covers password (Application), email/SMS passwordless, passkeys, and Lightning Login.
    // SSO, API/OAuth, certificate, and portal/community login types are intentionally excluded.
    @TestVisible
    private static final Set<String> DIRECT_UI_NON_SSO_LOGIN_TYPES = new Set<String>{
        'Application',
        'Passwordless Login',
        'Passwordless Login via Passkeys',
        'Lightning Login'
    };

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
        // Flag internal standard users who authenticated through a direct UI login rather than SSO.
        return DIRECT_UI_NON_SSO_LOGIN_TYPES.contains(loginEvent.LoginType)
            && 'Standard'.equals(loginEvent.UserType);
    }
}