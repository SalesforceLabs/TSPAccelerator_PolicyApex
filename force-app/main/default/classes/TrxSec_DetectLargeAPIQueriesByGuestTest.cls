/**
 * @description Test class for TrxSec_DetectLargeAPIQueriesByGuest
 */
@isTest
private class TrxSec_DetectLargeAPIQueriesByGuestTest {
    
    /**
     * Helper method to mock the guest profile IDs configuration
     */
    private static void mockGuestProfileIds(Set<String> profileIds) {
        TrxSec_DetectLargeAPIQueriesByGuest.guestProfileIds = profileIds;
    }
    
    /**
     * Test that large query by guest user triggers the policy
     */
    @isTest
    static void testLargeQueryByGuestUser() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Treat current user's profile ID as a Guest Profile ID
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        
        // Create an ApiEvent with RowsProcessed above threshold (1000)
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 1500
        );
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return true (Guest Profile + High Rows)
        System.assertEquals(true, result, 'Policy should trigger for guest user with large query');
    }
    
    /**
     * Test that query below threshold does not trigger policy for guest user
     */
    @isTest
    static void testQueryBelowThreshold() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Treat current user's profile ID as a Guest Profile ID
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        
        // Create an ApiEvent with RowsProcessed below threshold (1000)
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 500
        );
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (below threshold should not trigger)
        System.assertEquals(false, result, 'Query below threshold should not trigger policy');
    }
    
    /**
     * Test that query exactly at threshold does not trigger policy
     */
    @isTest
    static void testQueryAtThreshold() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Treat current user's profile ID as a Guest Profile ID
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        
        // Create an ApiEvent with RowsProcessed exactly at threshold (1000)
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 1000
        );
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (at threshold, not greater than)
        System.assertEquals(false, result, 'Query at exact threshold should not trigger policy');
    }
    
    /**
     * Test that query just above threshold would trigger (if guest user)
     */
    @isTest
    static void testQueryJustAboveThreshold() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Treat current user's profile ID as a Guest Profile ID
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        
        // Create an ApiEvent with RowsProcessed just above threshold (1001)
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 1001
        );
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should trigger
        System.assertEquals(true, result, 'Query just above threshold should trigger policy');
    }
    
    /**
     * Test that NON-guest user does NOT trigger policy even with large query
     */
    @isTest
    static void testNonGuestUserLargeQuery() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Ensure current user's profile ID is NOT in the guest list
        mockGuestProfileIds(new Set<String>{'00e000000000000AAA'});
        
        // Create an ApiEvent with RowsProcessed above threshold
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 5000
        );
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (Not a guest user)
        System.assertEquals(false, result, 'Policy should not trigger for non-guest user');
    }
    
    /**
     * Test that null RowsProcessed does not trigger policy
     */
    @isTest
    static void testNullRowsProcessed() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Treat current user's profile ID as a Guest Profile ID
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        
        // Create an ApiEvent with null RowsProcessed
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = null
        );
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (null RowsProcessed should not trigger)
        System.assertEquals(false, result, 'Null RowsProcessed should not trigger policy');
    }
    
    /**
     * Test that zero RowsProcessed does not trigger policy
     */
    @isTest
    static void testZeroRowsProcessed() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Treat current user's profile ID as a Guest Profile ID
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        
        // Create an ApiEvent with zero RowsProcessed
        ApiEvent testEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 0
        );
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (zero rows should not trigger)
        System.assertEquals(false, result, 'Zero RowsProcessed should not trigger policy');
    }
    
    /**
     * Test various RowsProcessed values
     */
    @isTest
    static void testVariousRowsProcessedValues() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Treat current user's profile ID as a Guest Profile ID
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        
        // Test very large number
        ApiEvent largeEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 999999
        );
        Boolean largeResult = policy.evaluate((SObject)largeEvent);
        System.assertEquals(true, largeResult, 'Very large query should trigger policy');
        
        // Test negative number (edge case)
        ApiEvent negativeEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = -100
        );
        System.assertEquals(false, policy.evaluate((SObject)negativeEvent), 
            'Negative RowsProcessed should not trigger policy');
        
        // Test small positive number
        ApiEvent smallEvent = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 1
        );
        System.assertEquals(false, policy.evaluate((SObject)smallEvent), 
            'Small RowsProcessed should not trigger policy');
    }
    
    /**
     * Test that null event returns false
     */
    @isTest
    static void testNullEvent() {
        // Evaluate the policy with null event
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)null);
        
        // Should return false (null event is handled by switch statement)
        System.assertEquals(false, result, 'Null event should not trigger policy');
    }
    
    /**
     * Test that a non-ApiEvent returns false
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
        
        // Evaluate the policy
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (non-ApiEvent should not trigger policy)
        System.assertEquals(false, result, 'Non-ApiEvent should not trigger policy');
    }
    
    /**
     * Test caching behavior
     */
    @isTest
    static void testCachingBehavior() {
        // Get current user
        User currentUser = [SELECT Id, Username, ProfileId FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        
        ApiEvent event = new ApiEvent(
            UserId = currentUser.Id,
            Username = currentUser.Username,
            RowsProcessed = 2000
        );
        
        // 1. Mock configuration to EXCLUDE current user
        mockGuestProfileIds(new Set<String>{'00e000000000000AAA'});
        System.assertEquals(false, policy.evaluate((SObject)event), 'Should be false when profile ID not in cache');
        
        // 2. Mock configuration to INCLUDE current user
        mockGuestProfileIds(new Set<String>{currentUser.ProfileId});
        System.assertEquals(true, policy.evaluate((SObject)event), 'Should be true when profile ID in cache');
    }
    
    /**
     * Test invalid user ID handling
     */
    @isTest
    static void testInvalidUserId() {
        // Create a fake user ID
        String fakeUserId = '005000000000000AAA';
        
        ApiEvent testEvent = new ApiEvent(
            UserId = fakeUserId,
            Username = 'test@example.com',
            RowsProcessed = 3000
        );
        
        TrxSec_DetectLargeAPIQueriesByGuest policy = new TrxSec_DetectLargeAPIQueriesByGuest();
        
        // Should handle empty user query result gracefully
        try {
            Boolean result = policy.evaluate((SObject)testEvent);
            System.assertEquals(false, result, 'Should return false for invalid user');
        } catch (Exception e) {
            System.assert(false, 'Should not throw exception for invalid user: ' + e.getMessage());
        }
    }
}
