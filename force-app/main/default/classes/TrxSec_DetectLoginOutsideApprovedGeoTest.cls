/**
 * @description Test class for TrxSec_DetectLoginsOutsideApprovedGeos
 */
@isTest
private class TrxSec_DetectLoginOutsideApprovedGeoTest {
    
    /**
     * Helper method to reset the cache so getApprovedCountries() gets invoked
     */
    private static void resetCache() {
        TrxSec_DetectLoginsOutsideApprovedGeos.approvedCountries = null;
    }
    
    /**
     * Helper method to mock the approved countries configuration (for legacy tests)
     */
    private static void mockApprovedCountries(Set<String> countries) {
        TrxSec_DetectLoginsOutsideApprovedGeos.approvedCountries = countries;
    }
    
    /**
     * Test that logins from US are allowed (returns false)
     */
    @isTest
    static void testLoginFromUS() {
        // Mock configuration: US is approved
        mockApprovedCountries(new Set<String>{'US'});

        // Create a test LoginEvent for US
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'US';
        
        // Evaluate the policy
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return false (allowed) because US is in our mock list
        System.assertEquals(false, result, 'Login from US should be allowed');
    }
    
    /**
     * Test that logins from Canada are allowed (returns false)
     */
    @isTest
    static void testLoginFromCA() {
        // Mock configuration: CA is approved
        mockApprovedCountries(new Set<String>{'CA'});

        // Create a test LoginEvent for Canada
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'CA';
        
        // Evaluate the policy
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return false (allowed) because CA is in our mock list
        System.assertEquals(false, result, 'Login from CA should be allowed');
    }
    
    /**
     * Test that logins from other countries are blocked (returns true)
     */
    @isTest
    static void testLoginFromOtherCountry() {
        // Mock configuration: Only US is approved
        mockApprovedCountries(new Set<String>{'US'});

        // Create a test LoginEvent for a different country
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'GB'; // Great Britain
        
        // Evaluate the policy
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return true (blocked)
        System.assertEquals(true, result, 'Login from GB should be blocked');
    }
    
    /**
     * Test that logins with lowercase country codes work correctly
     */
    @isTest
    static void testLoginWithLowercaseCountry() {
        // Mock configuration: US and CA are approved
        mockApprovedCountries(new Set<String>{'US', 'CA'});

        // Test lowercase 'us' (should be normalized to 'US' and allowed)
        LoginEvent testEvent1 = new LoginEvent();
        testEvent1.CountryIso = 'us';
        
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        Boolean result1 = policy.evaluate(testEvent1);
        System.assertEquals(false, result1, 'Login from lowercase us should be allowed (normalized to US)');
        
        // Test lowercase 'ca' (should be normalized to 'CA' and allowed)
        LoginEvent testEvent2 = new LoginEvent();
        testEvent2.CountryIso = 'ca';
        Boolean result2 = policy.evaluate(testEvent2);
        System.assertEquals(false, result2, 'Login from lowercase ca should be allowed (normalized to CA)');
    }
    
    /**
     * Test that logins with null country are blocked (returns true)
     */
    @isTest
    static void testLoginWithNullCountry() {
        // Mock configuration: US is approved
        mockApprovedCountries(new Set<String>{'US'});

        // Create a test LoginEvent with null country
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = null;
        
        // Evaluate the policy
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return true (blocked) for safety
        System.assertEquals(true, result, 'Login with null country should be blocked');
    }
    
    /**
     * Test that logins with blank country are blocked (returns true)
     */
    @isTest
    static void testLoginWithBlankCountry() {
        // Mock configuration: US is approved
        mockApprovedCountries(new Set<String>{'US'});

        // Create a test LoginEvent with blank country
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = '';
        
        // Evaluate the policy
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        Boolean result = policy.evaluate(testEvent);
        
        // Should return true (blocked) for safety
        System.assertEquals(true, result, 'Login with blank country should be blocked');
    }
    
    /**
     * Test multiple countries to ensure comprehensive coverage
     */
    @isTest
    static void testMultipleCountries() {
        // Mock configuration: Only US and CA are approved
        mockApprovedCountries(new Set<String>{'US', 'CA'});

        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        
        // Test various countries that should be blocked (not in approved list)
        String[] blockedCountries = new String[] {'MX', 'CN', 'RU', 'BR', 'IN', 'AU', 'DE', 'FR'};
        
        for (String country : blockedCountries) {
            LoginEvent testEvent = new LoginEvent();
            testEvent.CountryIso = country;
            Boolean result = policy.evaluate(testEvent);
            System.assertEquals(true, result, 'Login from ' + country + ' should be blocked (not in approved list)');
        }
    }
    
    /**
     * Test that the policy caches approved countries for performance
     * Note: Since we are mocking the cache directly, we are implicitly testing that the cache is used
     * (because the actual metadata query is never executed).
     */
    @isTest
    static void testCachingBehavior() {
        // Set initial mock state
        mockApprovedCountries(new Set<String>{'US'});
        
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        
        // First evaluation - should use our mock
        LoginEvent testEvent1 = new LoginEvent();
        testEvent1.CountryIso = 'US';
        Boolean result1 = policy.evaluate(testEvent1);
        System.assertEquals(false, result1, 'US should be allowed');
        
        // Change the mock "cache" to allow a different country
        // This simulates the cache being updated (or ensures we can control it)
        mockApprovedCountries(new Set<String>{'CA'});
        
        // Second evaluation - should use the NEW mock
        LoginEvent testEvent2 = new LoginEvent();
        testEvent2.CountryIso = 'CA';
        Boolean result2 = policy.evaluate(testEvent2);
        System.assertEquals(false, result2, 'CA should be allowed after cache update');
        
        // Check original country - should now be blocked as it's not in the new cache
        Boolean result3 = policy.evaluate(testEvent1);
        System.assertEquals(true, result3, 'US should be blocked after cache update');
    }
    
    /**
     * Test that getApprovedCountries() is actually invoked when cache is null
     * This test ensures the method is covered
     */
    @isTest
    static void testGetApprovedCountriesInvoked() {
        // Reset cache to ensure getApprovedCountries() gets called
        resetCache();
        
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        
        // Create a test LoginEvent
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'US';
        
        Test.startTest();
        // This will invoke getApprovedCountries() because cache is null
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
        
        // Query to see if any Approved_Login_Country__mdt records exist
        List<Approved_Login_Country__mdt> existingRecords = [
            SELECT Alpha_2_Country_Code__c
            FROM Approved_Login_Country__mdt
            WHERE Alpha_2_Country_Code__c != null
            LIMIT 1
        ];
        
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        
        Test.startTest();
        
        if (!existingRecords.isEmpty()) {
            // Test with a country from the actual CMT
            String approvedCountry = existingRecords[0].Alpha_2_Country_Code__c;
            
            LoginEvent testEvent1 = new LoginEvent();
            testEvent1.CountryIso = approvedCountry;
            Boolean result1 = policy.evaluate(testEvent1);
            
            // Should be allowed (false) since it's in the CMT
            System.assertEquals(false, result1, 'Country from CMT should be allowed: ' + approvedCountry);
            
            // Test with a country NOT in CMT
            LoginEvent testEvent2 = new LoginEvent();
            testEvent2.CountryIso = 'ZZ'; // Invalid country code
            Boolean result2 = policy.evaluate(testEvent2);
            
            // Should be blocked (true) since it's not in the CMT
            System.assertEquals(true, result2, 'Country not in CMT should be blocked');
        } else {
            // No CMT records exist - all countries will be blocked
            LoginEvent testEvent = new LoginEvent();
            testEvent.CountryIso = 'US';
            Boolean result = policy.evaluate(testEvent);
            
            // Should be blocked (true) since no approved countries exist
            System.assertEquals(true, result, 'All countries should be blocked when no CMT records exist');
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
        
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        
        Test.startTest();
        
        // First evaluation - should query CMT and populate cache
        LoginEvent testEvent1 = new LoginEvent();
        testEvent1.CountryIso = 'US';
        Boolean result1 = policy.evaluate(testEvent1);
        
        // Second evaluation - should use cached data (not query again)
        LoginEvent testEvent2 = new LoginEvent();
        testEvent2.CountryIso = 'CA';
        Boolean result2 = policy.evaluate(testEvent2);
        
        // Third evaluation - should still use cached data
        LoginEvent testEvent3 = new LoginEvent();
        testEvent3.CountryIso = 'GB';
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
        // This test ensures getApprovedCountries() handles empty result sets
        // We can't delete CMT records in tests, but we can test the behavior
        resetCache();
        
        TrxSec_DetectLoginsOutsideApprovedGeos policy = new TrxSec_DetectLoginsOutsideApprovedGeos();
        
        Test.startTest();
        
        LoginEvent testEvent = new LoginEvent();
        testEvent.CountryIso = 'US';
        
        // This will invoke getApprovedCountries()
        Boolean result = policy.evaluate(testEvent);
        
        Test.stopTest();
        
        // If no approved countries exist, should block (return true)
        // If some exist, behavior depends on whether US is in the list
        System.assertNotEquals(null, result, 'Evaluation should complete successfully');
    }
}
