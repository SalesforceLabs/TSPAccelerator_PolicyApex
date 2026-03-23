/**
 * @description Transaction Security Policy condition to detect large API queries performed by guest users
 */
global with sharing class TrxSec_DetectLargeAPIQueriesByGuest implements TxnSecurity.EventCondition {
    
    // Define the threshold for record count returned by a guest user query
    private static final Integer RECORD_COUNT_THRESHOLD = 1000;
    
    // Static set to cache guest profile IDs for performance and testing
    @TestVisible
    private static Set<String> guestProfileIds;
    
    global Boolean evaluate(SObject event) {
        switch on event {
            when ApiEvent apiEvent {
                return evaluate(apiEvent);
            }
            when else {
                return false;
            }
        }
    }
    
    private Boolean evaluate(ApiEvent apiEvent) {
        // Initialize cache if null
        if (guestProfileIds == null) {
            guestProfileIds = new Set<String>();
            for (Guest_Profile_Id__mdt guestProfile : [
                SELECT Guest_Profile_Id__c 
                FROM Guest_Profile_Id__mdt
                WHERE Guest_Profile_Id__c != null
            ]) {
                guestProfileIds.add(guestProfile.Guest_Profile_Id__c);
            }
        }
        
        // Get the user's profile ID
        // We need to query the user to get their ProfileId
        List<User> users = [
            SELECT Id, ProfileId 
            FROM User 
            WHERE Id = :apiEvent.UserId 
            LIMIT 1
        ];
        
        if (users.isEmpty()) {
            return false;
        }
        
        User u = users[0];
        
        // If user has a guest profile and the query returned too many rows, flag it
        if (guestProfileIds.contains(u.ProfileId)) {
            if (apiEvent.RowsProcessed != null && apiEvent.RowsProcessed > RECORD_COUNT_THRESHOLD) {
                return true;
            }
        }
        
        return false;
    }
}
