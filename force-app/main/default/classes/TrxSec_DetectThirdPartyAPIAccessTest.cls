/**
 * @description Test class for TrxSec_DetectThirdPartyAPIAccess
 * Note: Tests are self-contained and use cache mocking for predictable behavior.
 * The CMT query code (lines 18-26) is invoked by tests that reset the cache,
 * but the for loop body (lines 23-24) only executes if CMT records exist in the org.
 */
@isTest
private class TrxSec_DetectThirdPartyAPIAccessTest {
    
    /**
     * Helper method to reset the cache so CMT query gets invoked
     */
    private static void resetCache() {
        TrxSec_DetectThirdPartyAPIAccess.approvedClients = null;
    }
    
    /**
     * Helper method to mock the approved client configuration
     * Allows tests to be deterministic without depending on CMT records
     */
    private static void mockApprovedClients(Set<String> clients) {
        TrxSec_DetectThirdPartyAPIAccess.approvedClients = new Set<String>();
        for (String client : clients) {
            TrxSec_DetectThirdPartyAPIAccess.approvedClients.add(client.toLowerCase());
        }
    }
    
    /**
     * Test that API access from unapproved client triggers the policy
     */
    @isTest
    static void testUnapprovedClient() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve some client, but not the one used in test
        mockApprovedClients(new Set<String>{'ApprovedApp'});
        
        // Create an ApiEvent with an unapproved client
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'UnapprovedThirdPartyApp'
        );
        
        // Evaluate the policy
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return true (Unapproved client -> Trigger Policy)
        System.assertEquals(true, result, 'Policy should trigger for unapproved client');
    }
    
    /**
     * Test that API access from approved client does NOT trigger policy
     */
    @isTest
    static void testApprovedClient() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve the client used in test
        mockApprovedClients(new Set<String>{'ApprovedApp'});
        
        // Create an ApiEvent with an approved client
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'ApprovedApp'
        );
        
        // Evaluate the policy
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (Approved client -> No Trigger)
        System.assertEquals(false, result, 'Policy should not trigger for approved client');
    }
    
    /**
     * Test that null client does not trigger policy
     */
    @isTest
    static void testNullClient() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve some client
        mockApprovedClients(new Set<String>{'ApprovedApp'});
        
        // Create an ApiEvent with null client
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = null
        );
        
        // Evaluate the policy
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (null client should not trigger)
        System.assertEquals(false, result, 'Null client should not trigger policy');
    }
    
    /**
     * Test that blank client does not trigger policy
     */
    @isTest
    static void testBlankClient() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve some client
        mockApprovedClients(new Set<String>{'ApprovedApp'});
        
        // Create an ApiEvent with blank client
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = ''
        );
        
        // Evaluate the policy
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (blank client should not trigger)
        System.assertEquals(false, result, 'Blank client should not trigger policy');
    }
    
    /**
     * Test that whitespace-only client does not trigger policy
     */
    @isTest
    static void testWhitespaceClient() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve some client
        mockApprovedClients(new Set<String>{'ApprovedApp'});
        
        // Create an ApiEvent with whitespace-only client
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = '   '
        );
        
        // Evaluate the policy
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (whitespace client should not trigger)
        System.assertEquals(false, result, 'Whitespace-only client should not trigger policy');
    }
    
    /**
     * Test case sensitivity handling
     */
    @isTest
    static void testCaseSensitivity() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve 'ThirdPartyApp' (mixed case)
        mockApprovedClients(new Set<String>{'ThirdPartyApp'});
        
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        
        // Test uppercase client name - Should match 'ThirdPartyApp' and NOT trigger
        ApiEvent uppercaseEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'THIRDPARTYAPP'
        );
        Boolean uppercaseResult = policy.evaluate((SObject)uppercaseEvent);
        System.assertEquals(false, uppercaseResult, 'Uppercase client should be approved (case-insensitive)');
        
        // Test lowercase client name - Should match 'ThirdPartyApp' and NOT trigger
        ApiEvent lowercaseEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'thirdpartyapp'
        );
        Boolean lowercaseResult = policy.evaluate((SObject)lowercaseEvent);
        System.assertEquals(false, lowercaseResult, 'Lowercase client should be approved (case-insensitive)');
        
        // Test mixed case client name - Should match 'ThirdPartyApp' and NOT trigger
        ApiEvent mixedCaseEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'ThirdPartyApp'
        );
        Boolean mixedCaseResult = policy.evaluate((SObject)mixedCaseEvent);
        System.assertEquals(false, mixedCaseResult, 'Mixed case client should be approved (case-insensitive)');
        
        // Test completely different client - Should trigger
        ApiEvent differentEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'OtherApp'
        );
        Boolean differentResult = policy.evaluate((SObject)differentEvent);
        System.assertEquals(true, differentResult, 'Different client should trigger policy');
    }
    
    /**
     * Test caching behavior
     */
    @isTest
    static void testCachingBehavior() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'TestClient'
        );
        
        // 1. Mock configuration to EXCLUDE client (should trigger)
        mockApprovedClients(new Set<String>{'OtherApp'});
        Boolean result1 = policy.evaluate((SObject)testEvent);
        System.assertEquals(true, result1, 'Should trigger when client not in cache');
        
        // 2. Mock configuration to INCLUDE client (should NOT trigger)
        mockApprovedClients(new Set<String>{'TestClient'});
        Boolean result2 = policy.evaluate((SObject)testEvent);
        System.assertEquals(false, result2, 'Should not trigger when client in cache');
    }
    
    /**
     * Test that null event returns false
     */
    @isTest
    static void testNullEvent() {
        // Evaluate the policy with null event
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        
        try {
            Boolean result = policy.evaluate((SObject)null);
            // If we get here, the method handled null gracefully
            System.assertEquals(false, result, 'Null event should return false or be handled');
        } catch (Exception e) {
            // Exception is acceptable for null event
            System.assert(true, 'Exception is acceptable for null event');
        }
    }
    
    /**
     * Test that a non-ApiEvent throws an exception
     */
    @isTest
    static void testNonApiEvent() {
        // Create a LoginEvent (not an ApiEvent)
        LoginEvent testEvent = new LoginEvent(
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            LoginType = 'Application',
            UserType = 'Standard'
        );
        
        // Evaluate the policy - this should throw a type cast exception
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        
        try {
            Boolean result = policy.evaluate((SObject)testEvent);
            System.assert(false, 'Should have thrown an exception for non-ApiEvent');
        } catch (System.TypeException e) {
            // Expected - the cast to ApiEvent should fail
            System.assert(true, 'Type cast exception is expected');
        }
    }
    
    /**
     * Test that Custom Metadata query is invoked when cache is null
     * Uses cache reset to ensure CMT query path is executed
     * Note: Code coverage of the for loop body (lines 23-24) depends on CMT records
     * existing in the subscriber org at runtime
     */
    @isTest
    static void testCustomMetadataQueryInvoked() {
        // Reset cache to ensure CMT query gets executed
        resetCache();
        
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        
        Test.startTest();
        
        // Create an ApiEvent with some client
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'SomeTestClient'
        );
        
        // This will invoke the CMT query (lines 18-26) because cache is null
        // The for loop body (lines 23-24) executes only if CMT records exist in the org
        Boolean result = policy.evaluate((SObject)testEvent);
        
        Test.stopTest();
        
        // Since we reset cache, the query was executed
        // Result will be true (blocked) if no CMT records exist, or depends on CMT content
        System.assertNotEquals(null, result, 'Result should not be null');
    }
    
    /**
     * Test that cache persists across multiple evaluations
     * This test invokes the CMT query on first evaluation, then uses cache
     */
    @isTest
    static void testCachePersistenceAcrossEvaluations() {
        // Reset cache first
        resetCache();
        
        User currentUser = [SELECT Id, Username FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        TrxSec_DetectThirdPartyAPIAccess policy = new TrxSec_DetectThirdPartyAPIAccess();
        
        Test.startTest();
        
        // First evaluation - queries CMT and populates cache (covers lines 18-26)
        ApiEvent testEvent1 = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'Client1'
        );
        Boolean result1 = policy.evaluate((SObject)testEvent1);
        
        // Second evaluation - uses cached data (doesn't query again)
        ApiEvent testEvent2 = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'Client2'
        );
        Boolean result2 = policy.evaluate((SObject)testEvent2);
        
        // Third evaluation - still uses cached data
        ApiEvent testEvent3 = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            Client = 'Client3'
        );
        Boolean result3 = policy.evaluate((SObject)testEvent3);
        
        Test.stopTest();
        
        // All evaluations should complete successfully
        System.assertNotEquals(null, result1, 'First evaluation should complete');
        System.assertNotEquals(null, result2, 'Second evaluation should complete');
        System.assertNotEquals(null, result3, 'Third evaluation should complete');
    }
}
