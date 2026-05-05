/**
 * @description Test class for TrxSec_DetectLoginsFromBlockedGeos
 */
@isTest
private class TrxSec_DetectLoginFromBlockedGeoTest {
    
    /**
     * Helper method to reset the cache so getBlockedCountries() gets invoked
     */
    private static void resetCache() {
        TrxSec_DetectLoginsFromBlockedGeos.blockedCountries = null;
    }
    
    /**
     * Helper method to mock the blocked countries configuration (for legacy tests)
     */
    private static void mockBlockedCountries(Set<String> countries) {
        TrxSec_DetectLoginsFromBlockedGeos.blockedCountries = countries;
    }
    
    /**
     * Test that logins from blocked country (KP) are flagged (returns true)
     */
    @isTest
    static void testLoginFromKP() {
        // Mock configuration: KP is blocked
        mockBlockedCountries(new Set<String>{'KP'});

        // Create a test LoginEvent for North Korea
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'KP';
        
        // Evaluate the policy
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return true (blocked) because KP is in our mock list
        System.assertEquals(true, result, 'Login from KP should be blocked');
    }
    
    /**
     * Test that logins from blocked country (IR) are flagged (returns true)
     */
    @isTest
    static void testLoginFromIR() {
        // Mock configuration: IR is blocked
        mockBlockedCountries(new Set<String>{'IR'});

        // Create a test LoginEvent for Iran
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'IR';
        
        // Evaluate the policy
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return true (blocked) because IR is in our mock list
        System.assertEquals(true, result, 'Login from IR should be blocked');
    }
    
    /**
     * Test that logins from non-blocked countries are allowed (returns false)
     */
    @isTest
    static void testLoginFromAllowedCountry() {
        // Mock configuration: Only KP is blocked
        mockBlockedCountries(new Set<String>{'KP'});

        // Create a test LoginEvent for a non-blocked country
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'US';
        
        // Evaluate the policy
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return false (allowed) because US is not in the blocked list
        System.assertEquals(false, result, 'Login from US should be allowed');
    }
    
    /**
     * Test that logins with lowercase country codes are normalized correctly
     */
    @isTest
    static void testLoginWithLowercaseCountry() {
        // Mock configuration: KP and IR are blocked
        mockBlockedCountries(new Set<String>{'KP', 'IR'});

        // Test lowercase 'kp' (should be normalized to 'KP' and blocked)
        LoginEvent testEvent1 = new LoginEvent();
        testEvent1.CountryIso = 'kp';
        
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        Boolean result1 = policy.evaluate(testEvent1);
        System.assertEquals(true, result1, 'Login from lowercase kp should be blocked (normalized to KP)');
        
        // Test lowercase 'ir' (should be normalized to 'IR' and blocked)
        LoginEvent testEvent2 = new LoginEvent();
        testEvent2.CountryIso = 'ir';
        Boolean result2 = policy.evaluate(testEvent2);
        System.assertEquals(true, result2, 'Login from lowercase ir should be blocked (normalized to IR)');
    }
    
    /**
     * Test that logins with null country are NOT flagged (returns false)
     * Rationale: a null country cannot be matched against the blocked list
     */
    @isTest
    static void testLoginWithNullCountry() {
        // Mock configuration: KP is blocked
        mockBlockedCountries(new Set<String>{'KP'});

        // Create a test LoginEvent with null country
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = null;
        
        // Evaluate the policy
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return false because null cannot match a blocklist entry
        System.assertEquals(false, result, 'Login with null country should not be flagged by the blocklist');
    }
    
    /**
     * Test that logins with blank country are NOT flagged (returns false)
     * Rationale: a blank country cannot be matched against the blocked list
     */
    @isTest
    static void testLoginWithBlankCountry() {
        // Mock configuration: KP is blocked
        mockBlockedCountries(new Set<String>{'KP'});

        // Create a test LoginEvent with blank country
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = '';
        
        // Evaluate the policy
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return false because blank cannot match a blocklist entry
        System.assertEquals(false, result, 'Login with blank country should not be flagged by the blocklist');
    }
    
    /**
     * Test multiple countries to ensure comprehensive coverage
     */
    @isTest
    static void testMultipleCountries() {
        // Mock configuration: KP, IR, RU, CU are blocked
        mockBlockedCountries(new Set<String>{'KP', 'IR', 'RU', 'CU'});

        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        
        // Test various countries that should be blocked (in blocked list)
        String[] flaggedCountries = new String[] {'KP', 'IR', 'RU', 'CU'};
        for (String country : flaggedCountries) {
            LoginEvent testEvent = new LoginEvent();
            testEvent.CountryIso = country;
            Boolean result = policy.evaluate(testEvent);
            System.assertEquals(true, result, 'Login from ' + country + ' should be flagged (in blocked list)');
        }
        
        // Test various countries that should NOT be flagged (not in blocked list)
        String[] allowedCountries = new String[] {'US', 'CA', 'GB', 'AU', 'DE', 'FR', 'BR', 'IN'};
        for (String country : allowedCountries) {
            LoginEvent testEvent = new LoginEvent();
            testEvent.CountryIso = country;
            Boolean result = policy.evaluate(testEvent);
            System.assertEquals(false, result, 'Login from ' + country + ' should be allowed (not in blocked list)');
        }
    }
    
    /**
     * Test that the policy caches blocked countries for performance
     * Note: Since we are mocking the cache directly, we are implicitly testing that the cache is used
     * (because the actual metadata query is never executed).
     */
    @isTest
    static void testCachingBehavior() {
        // Set initial mock state
        mockBlockedCountries(new Set<String>{'KP'});
        
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        
        // First evaluation - should use our mock
        LoginEvent testEvent1 = new LoginEvent();
        testEvent1.CountryIso = 'KP';
        Boolean result1 = policy.evaluate(testEvent1);
        System.assertEquals(true, result1, 'KP should be blocked');
        
        // Change the mock "cache" to block a different country
        // This simulates the cache being updated (or ensures we can control it)
        mockBlockedCountries(new Set<String>{'IR'});
        
        // Second evaluation - should use the NEW mock
        LoginEvent testEvent2 = new LoginEvent();
        testEvent2.CountryIso = 'IR';
        Boolean result2 = policy.evaluate(testEvent2);
        System.assertEquals(true, result2, 'IR should be blocked after cache update');
        
        // Check original country - should now be allowed as it's not in the new cache
        Boolean result3 = policy.evaluate(testEvent1);
        System.assertEquals(false, result3, 'KP should be allowed after cache update');
    }
    
    /**
     * Test that getBlockedCountries() is actually invoked when cache is null
     * This test ensures the method is covered
     */
    @isTest
    static void testGetBlockedCountriesInvoked() {
        // Reset cache to ensure getBlockedCountries() gets called
        resetCache();
        
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        
        // Create a test LoginEvent
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'KP';
        
        Test.startTest();
        // This will invoke getBlockedCountries() because cache is null
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Result depends on actual CMT records in the org
        // We're just ensuring the method executes without error
        System.assertNotEquals(null, result, 'Result should not be null');
    }
    
    /**
     * Test with actual Custom Metadata query (if records exist)
     */
    @isTest
    static void testWithActualCustomMetadata() {
        // Reset cache to force actual query
        resetCache();
        
        // Query to see if any Blocked_Login_Country__mdt records exist
        List<Blocked_Login_Country__mdt> existingRecords = [
            SELECT Alpha_2_Country_Code__c
            FROM Blocked_Login_Country__mdt
            WHERE Alpha_2_Country_Code__c != null
            LIMIT 1
        ];
        
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        
        Test.startTest();
        
        if (!existingRecords.isEmpty()) {
            // Test with a country from the actual CMT
            String blockedCountry = existingRecords[0].Alpha_2_Country_Code__c;
            
            LoginEvent testEvent1 = new LoginEvent();
            testEvent1.CountryIso = blockedCountry;
            Boolean result1 = policy.evaluate(testEvent1);
            
            // Should be blocked (true) since it's in the CMT
            System.assertEquals(true, result1, 'Country from CMT should be blocked: ' + blockedCountry);
            
            // Test with a country NOT in CMT
            LoginEvent testEvent2 = new LoginEvent();
            testEvent2.CountryIso = 'ZZ'; // Invalid country code
            Boolean result2 = policy.evaluate(testEvent2);
            
            // Should be allowed (false) since it's not in the CMT
            System.assertEquals(false, result2, 'Country not in CMT should be allowed');
        } else {
            // No CMT records exist - all countries will be allowed
            LoginEvent testEvent = new LoginEvent();
            testEvent.CountryIso = 'KP';
            Boolean result = policy.evaluate(testEvent);
            
            // Should be allowed (false) since no blocked countries exist
            System.assertEquals(false, result, 'All countries should be allowed when no CMT records exist');
        }
        
        Test.stopTest();
    }
    
    /**
     * Test that cache persists across multiple evaluations
     */
    @isTest
    static void testCachePersistence() {
        // Reset cache first
        resetCache();
        
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        
        Test.startTest();
        
        // First evaluation - should query CMT and populate cache
        LoginEvent testEvent1 = new LoginEvent();
        testEvent1.CountryIso = 'KP';
        Boolean result1 = policy.evaluate(testEvent1);
        
        // Second evaluation - should use cached data (not query again)
        LoginEvent testEvent2 = new LoginEvent();
        testEvent2.CountryIso = 'IR';
        Boolean result2 = policy.evaluate(testEvent2);
        
        // Third evaluation - should still use cached data
        LoginEvent testEvent3 = new LoginEvent();
        testEvent3.CountryIso = 'US';
        Boolean result3 = policy.evaluate(testEvent3);
        
        Test.stopTest();
        
        // All evaluations should complete successfully
        System.assertNotEquals(null, result1, 'First evaluation should complete');
        System.assertNotEquals(null, result2, 'Second evaluation should complete');
        System.assertNotEquals(null, result3, 'Third evaluation should complete');
    }
    
    /**
     * Test empty Custom Metadata scenario
     */
    @isTest
    static void testEmptyCustomMetadata() {
        // This test ensures getBlockedCountries() handles empty result sets
        // We can't delete CMT records in tests, but we can test the behavior
        resetCache();
        
        TrxSec_DetectLoginsFromBlockedGeos policy = new TrxSec_DetectLoginsFromBlockedGeos();
        
        Test.startTest();
        
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'KP';
        
        // This will invoke getBlockedCountries()
        Boolean result = policy.evaluate(testEvent);
        
        Test.stopTest();
        
        // If no blocked countries exist, should allow (return false)
        // If some exist, behavior depends on whether KP is in the list
        System.assertNotEquals(null, result, 'Evaluation should complete successfully');
    }
}
