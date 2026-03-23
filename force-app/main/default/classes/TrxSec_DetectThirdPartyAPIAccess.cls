/**
 * @description Transaction Security Policy condition to detect API access from unapproved third-party applications
 */
global with sharing class TrxSec_DetectThirdPartyAPIAccess implements TxnSecurity.EventCondition {
    
    // Static set to cache approved client names for performance and testing
    @TestVisible
    private static Set<String> approvedClients;
    
    global Boolean evaluate(SObject event) {
        ApiEvent apiEvent = (ApiEvent) event;
        
        if (apiEvent == null || String.isBlank(apiEvent.Client)) {
            return false; // Can't evaluate without client app info
        }
        
        // Initialize cache if null
        if (approvedClients == null) {
            approvedClients = new Set<String>();
            for (Approved_API_Client__mdt entry : [
                SELECT Client_Name__c 
                FROM Approved_API_Client__mdt
            ]) {
                approvedClients.add(entry.Client_Name__c.toLowerCase());
            }
        }
        
        // Normalize input and check
        String incomingClient = apiEvent.Client.toLowerCase();
        return !approvedClients.contains(incomingClient);
    }
}
