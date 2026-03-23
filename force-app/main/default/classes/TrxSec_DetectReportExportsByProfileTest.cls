/**
 * @description Test class for TrxSec_DetectReportExportsByProfile
 */
@isTest
private class TrxSec_DetectReportExportsByProfileTest {
    
    /**
     * Helper method to mock the approved profiles configuration
     */
    private static void mockApprovedProfiles(Set<String> profiles) {
        TrxSec_DetectReportExportsByProfile.approvedProfiles = profiles;
    }
    
    /**
     * Test that report export operation by unapproved profile triggers policy
     */
    @isTest
    static void testReportExportByUnapprovedProfile() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve a different profile, so current user is unapproved
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});
        
        // Create a ReportEvent with Operation='ReportExported'
        ReportEvent testEvent = new ReportEvent(
            Operation = 'ReportExported',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        
        // Evaluate the policy
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return true (Unapproved profile + Export)
        System.assertEquals(true, result, 'Policy should trigger for unapproved profile export');
    }
    
    /**
     * Test that report export operation by approved profile does NOT trigger policy
     */
    @isTest
    static void testReportExportByApprovedProfile() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: Approve current user's profile
        mockApprovedProfiles(new Set<String>{currentUser.Profile.Name});
        
        // Create a ReportEvent with Operation='ReportExported'
        ReportEvent testEvent = new ReportEvent(
            Operation = 'ReportExported',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        
        // Evaluate the policy
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (Approved profile + Export)
        System.assertEquals(false, result, 'Policy should not trigger for approved profile export');
    }
    
    /**
     * Test that non-export operations are not flagged, regardless of profile
     */
    @isTest
    static void testReportViewedOperation() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: User is unapproved (would trigger if exported)
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});
        
        // Create a ReportEvent with Operation='ReportViewed' (not exported)
        ReportEvent testEvent = new ReportEvent(
            Operation = 'ReportViewed',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        
        // Evaluate the policy
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (only ReportExported operations should trigger)
        System.assertEquals(false, result, 'ReportViewed operation should not trigger policy');
    }
    
    /**
     * Test various report operations
     */
    @isTest
    static void testVariousReportOperations() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: User is unapproved
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});
        
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        
        // Test ReportCreated
        ReportEvent createdEvent = new ReportEvent(
            Operation = 'ReportCreated',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        System.assertEquals(false, policy.evaluate((SObject)createdEvent), 
            'ReportCreated should not trigger policy');
        
        // Test ReportDeleted
        ReportEvent deletedEvent = new ReportEvent(
            Operation = 'ReportDeleted',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        System.assertEquals(false, policy.evaluate((SObject)deletedEvent), 
            'ReportDeleted should not trigger policy');
        
        // Test ReportUpdated
        ReportEvent updatedEvent = new ReportEvent(
            Operation = 'ReportUpdated',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        System.assertEquals(false, policy.evaluate((SObject)updatedEvent), 
            'ReportUpdated should not trigger policy');
    }
    
    /**
     * Test that null event returns false
     */
    @isTest
    static void testNullEvent() {
        // Evaluate the policy with null event
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        Boolean result = policy.evaluate((SObject)null);
        
        // Should return false (null event is handled by switch statement)
        System.assertEquals(false, result, 'Null event should not trigger policy');
    }
    
    /**
     * Test that a non-ReportEvent returns false
     */
    @isTest
    static void testNonReportEvent() {
        // Create a LoginEvent (not a ReportEvent)
        LoginEvent testEvent = new LoginEvent(
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            LoginType = 'Application',
            UserType = 'Standard'
        );
        
        // Evaluate the policy
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (non-ReportEvent should not trigger policy)
        System.assertEquals(false, result, 'Non-ReportEvent should not trigger policy');
    }
    
    /**
     * Test case sensitivity of Operation field
     */
    @isTest
    static void testOperationCaseSensitivity() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: User is unapproved
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});
        
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        
        // Test with lowercase operation
        ReportEvent lowercaseEvent = new ReportEvent(
            Operation = 'reportexported',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        System.assertEquals(false, policy.evaluate((SObject)lowercaseEvent), 
            'Lowercase operation should not match due to case sensitivity');
        
        // Test with uppercase operation
        ReportEvent uppercaseEvent = new ReportEvent(
            Operation = 'REPORTEXPORTED',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        System.assertEquals(false, policy.evaluate((SObject)uppercaseEvent), 
            'Uppercase operation should not match due to case sensitivity');
    }
    
    /**
     * Test with null or empty Operation
     */
    @isTest
    static void testNullOrEmptyOperation() {
        // Get current user for testing
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        // Mock configuration: User is unapproved
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});
        
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        
        // Test with null operation
        ReportEvent nullOpEvent = new ReportEvent(
            Operation = null,
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        System.assertEquals(false, policy.evaluate((SObject)nullOpEvent), 
            'Null operation should not trigger policy');
        
        // Test with empty string operation
        ReportEvent emptyOpEvent = new ReportEvent(
            Operation = '',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        System.assertEquals(false, policy.evaluate((SObject)emptyOpEvent), 
            'Empty operation should not trigger policy');
    }
    
    /**
     * Test caching behavior
     */
    @isTest
    static void testCachingBehavior() {
        // Get current user
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        
        ReportEvent exportEvent = new ReportEvent(
            Operation = 'ReportExported',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );
        
        // 1. Mock configuration to EXCLUDE current user (should trigger)
        mockApprovedProfiles(new Set<String>{'OtherProfile'});
        System.assertEquals(true, policy.evaluate((SObject)exportEvent), 
            'Should be true (blocked) when profile not in cache');
        
        // 2. Mock configuration to INCLUDE current user (should NOT trigger)
        mockApprovedProfiles(new Set<String>{currentUser.Profile.Name});
        System.assertEquals(false, policy.evaluate((SObject)exportEvent), 
            'Should be false (allowed) when profile in cache');
    }
    
    /**
     * Test invalid user ID handling
     */
    @isTest
    static void testInvalidUserId() {
        // Create a fake user ID
        String fakeUserId = '005000000000000AAA';
        
        ReportEvent testEvent = new ReportEvent(
            Operation = 'ReportExported',
            UserId = fakeUserId,
            Username = 'test@example.com'
        );
        
        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();
        
        // Should handle empty user query result gracefully
        try {
            Boolean result = policy.evaluate((SObject)testEvent);
            System.assertEquals(false, result, 'Should return false for invalid user');
        } catch (Exception e) {
            System.assert(false, 'Should not throw exception for invalid user: ' + e.getMessage());
        }
    }
}
