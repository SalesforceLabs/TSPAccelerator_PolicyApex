/**
 * @description Transaction Security Policy condition to detect logins using disallowed TLS cipher suites
 */
global with sharing class TrxSec_DetectTLSCipherSuiteLogin implements TxnSecurity.EventCondition {
    
    // Static set to cache allowed cipher suites for performance
    @TestVisible
    private static Set<String> allowedSuites;
    
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
        if (String.isBlank(loginEvent.CipherSuite)) {
            return false;
        }
        
        // Initialize cache if null
        if (allowedSuites == null) {
            allowedSuites = new Set<String>();
            for (Allowed_Cipher_Suite__mdt suite : [
                SELECT Cipher_Suite__c
                FROM Allowed_Cipher_Suite__mdt
            ]) {
                allowedSuites.add(suite.Cipher_Suite__c);
            }
        }
        
        return !allowedSuites.contains(loginEvent.CipherSuite);
    }
}
