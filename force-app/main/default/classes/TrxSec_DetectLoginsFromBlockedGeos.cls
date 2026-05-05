/**
 * @description Transaction Security Policy condition to detect logins from countries on the blocked list
 */
global with sharing class TrxSec_DetectLoginsFromBlockedGeos implements TxnSecurity.EventCondition {
    /**
     **********************************************************
     * DETECT LOGINS FROM COUNTRIES ON BLOCKED LIST
     **********************************************************
     * This policy evaluates LoginEvent and returns true when
     * the login originates from a country on the blocked list.
     * Blocked countries are configured in Blocked_Login_Country__mdt records.
     * Reference: https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_loginevent.htm
     */
    
    // Static set to cache blocked countries for performance
    @TestVisible
    private static Set<String> blockedCountries;
    
    global Boolean evaluate(SObject event) {
        // Cast the event to LoginEvent
        LoginEvent loginEvent = (LoginEvent) event;
        
        // Get the country from the login event
        String country = loginEvent.CountryIso;
        
        // Return true if country IS in blocked list (indicating a policy violation)
        // Return false if country is NOT in blocked list (allowed)
        if (String.isNotBlank(country)) {
            return isBlockedCountry(country);
        }
        
        // If country is blank/null, we cannot match it against the blocked list - do not flag
        return false;
    }
    
    /**
     * Helper method to check if a country is in the blocked list
     * @param country The country code from the LoginEvent
     * @return true if the country is blocked, false otherwise
     */
    private boolean isBlockedCountry(String country) {
        // Normalize the country code to uppercase for comparison
        String normalizedCountry = country.toUpperCase();
        
        // Get blocked countries from Custom Metadata (cached)
        if (blockedCountries == null) {
            blockedCountries = getBlockedCountries();
        }
        
        // Check if the country is in the blocked list
        return blockedCountries.contains(normalizedCountry);
    }
    
    /**
     * Query and cache blocked countries from Custom Metadata Type
     * @return Set of blocked country codes (uppercase)
     */
    private static Set<String> getBlockedCountries() {
        Set<String> countries = new Set<String>();
        
        // Query all Blocked_Login_Country__mdt records
        List<Blocked_Login_Country__mdt> blockedCountryRecords = [
            SELECT Alpha_2_Country_Code__c
            FROM Blocked_Login_Country__mdt
            WHERE Alpha_2_Country_Code__c != null
        ];
        
        // Build set of blocked country codes (normalized to uppercase)
        for (Blocked_Login_Country__mdt record : blockedCountryRecords) {
            if (String.isNotBlank(record.Alpha_2_Country_Code__c)) {
                countries.add(record.Alpha_2_Country_Code__c.toUpperCase());
            }
        }
        
        return countries;
    }
}

