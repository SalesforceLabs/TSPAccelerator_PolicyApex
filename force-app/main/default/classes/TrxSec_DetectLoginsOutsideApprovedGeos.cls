/**
 * @description Transaction Security Policy condition to detect logins from countries outside the approved list
 */
global with sharing class TrxSec_DetectLoginsOutsideApprovedGeos implements TxnSecurity.EventCondition {
    /**
     **********************************************************
     * DETECT LOGINS FROM COUNTRIES OUTSIDE APPROVED GEOS
     **********************************************************
     * This policy evaluates LoginEvent and returns true when
     * the login originates from a country outside the approved list.
     * Approved countries are configured in Approved_Login_Country__mdt records.
     * Reference: https://developer.salesforce.com/docs/atlas.en-us.platform_events.meta/platform_events/sforce_api_objects_loginevent.htm
     */
    
    // Static set to cache approved countries for performance
    @TestVisible
    private static Set<String> approvedCountries;
    
    global Boolean evaluate(SObject event) {
        // Cast the event to LoginEvent
        LoginEvent loginEvent = (LoginEvent) event;
        
        // Get the country from the login event
        String country = loginEvent.CountryIso;
        
        // Return true if country is NOT in approved list (indicating a policy violation)
        // Return false if country is in approved list (allowed)
        if (String.isNotBlank(country)) {
            return !isAllowedCountry(country);
        }
        
        // If country is blank/null, consider it suspicious
        return true;
    }
    
    /**
     * Helper method to check if a country is in the allowed list
     * @param country The country code from the LoginEvent
     * @return true if the country is allowed, false otherwise
     */
    private boolean isAllowedCountry(String country) {
        // Normalize the country code to uppercase for comparison
        String normalizedCountry = country.toUpperCase();
        
        // Get approved countries from Custom Metadata (cached)
        if (approvedCountries == null) {
            approvedCountries = getApprovedCountries();
        }
        
        // Check if the country is in the approved list
        return approvedCountries.contains(normalizedCountry);
    }
    
    /**
     * Query and cache approved countries from Custom Metadata Type
     * @return Set of approved country codes (uppercase)
     */
    private static Set<String> getApprovedCountries() {
        Set<String> countries = new Set<String>();
        
        // Query all Approved_Login_Country__mdt records
        List<Approved_Login_Country__mdt> approvedCountryRecords = [
            SELECT Alpha_2_Country_Code__c
            FROM Approved_Login_Country__mdt
            WHERE Alpha_2_Country_Code__c != null
        ];
        
        // Build set of approved country codes (normalized to uppercase)
        for (Approved_Login_Country__mdt record : approvedCountryRecords) {
            if (String.isNotBlank(record.Alpha_2_Country_Code__c)) {
                countries.add(record.Alpha_2_Country_Code__c.toUpperCase());
            }
        }
        
        return countries;
    }
}

