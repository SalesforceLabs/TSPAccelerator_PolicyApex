/**
 * @description Transaction Security Policy condition to detect report exports by users with unapproved profiles
 */
global with sharing class TrxSec_DetectReportExportsByProfile implements TxnSecurity.EventCondition {
    
    // Static set to cache approved profiles for performance and testing
    @TestVisible
    private static Set<String> approvedProfiles;
    
    global Boolean evaluate(SObject event) {
        switch on event {
            when ReportEvent reportEvent {
                return evaluate(reportEvent);
            }
            when else {
                return false;
            }
        }
    }
    
    private Boolean evaluate(ReportEvent reportEvent) {
        // Only evaluate if this is a report export operation
        if (!'ReportExported'.equals(reportEvent.Operation)) {
            return false;
        }
        
        // Initialize cache if null
        if (approvedProfiles == null) {
            approvedProfiles = new Set<String>();
            for (Approved_Profile__mdt profile : [
                SELECT Profile_Name__c 
                FROM Approved_Profile__mdt
                WHERE Profile_Name__c != null
            ]) {
                approvedProfiles.add(profile.Profile_Name__c);
            }
        }
        
        // Get the user's profile name
        List<User> users = [
            SELECT Id, Profile.Name 
            FROM User 
            WHERE Id = :reportEvent.UserId 
            LIMIT 1
        ];
        
        if (users.isEmpty()) {
            return false;
        }
        
        User u = users[0];
        
        // Return true if the user's profile is NOT in the approved list
        // This triggers the policy action
        return !approvedProfiles.contains(u.Profile.Name);
    }
}
