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
     * REGRESSION TEST for the export-operation guard defect.
     *
     * ReportEvent.Operation is a restricted picklist with exactly three export values:
     * ReportExported, ReportExportedAsynchronously and ReportExportedUsingExcelConnector. The guard
     * used to match only 'ReportExported' exactly, so an asynchronous export by an unapproved
     * profile was silently ignored. Salesforce routes large report exports through asynchronous
     * export, so this skipped precisely the high-volume exports the policy exists to catch.
     *
     * This test fails against the pre-fix code, which returns false for this event.
     */
    @isTest
    static void testAsynchronousExportByUnapprovedProfile() {
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});

        ReportEvent testEvent = new ReportEvent(
            Operation = 'ReportExportedAsynchronously',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );

        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();

        System.assertEquals(
            true,
            policy.evaluate((SObject)testEvent),
            'ReportExportedAsynchronously must be evaluated, not short-circuited by the guard'
        );
    }

    /**
     * The Excel connector is the third export path and must also be evaluated.
     */
    @isTest
    static void testExcelConnectorExportByUnapprovedProfile() {
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});

        ReportEvent testEvent = new ReportEvent(
            Operation = 'ReportExportedUsingExcelConnector',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );

        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();

        System.assertEquals(
            true,
            policy.evaluate((SObject)testEvent),
            'ReportExportedUsingExcelConnector must be evaluated, not short-circuited by the guard'
        );
    }

    /**
     * A real non-export Operation picklist value must not trigger the policy. 'ReportRunFromLightning'
     * is used rather than an invented value, so this genuinely exercises the guard.
     */
    @isTest
    static void testRealNonExportOperationDoesNotTrigger() {
        User currentUser = [SELECT Id, Username, Profile.Name FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1];
        mockApprovedProfiles(new Set<String>{'SomeOtherProfile'});

        ReportEvent testEvent = new ReportEvent(
            Operation = 'ReportRunFromLightning',
            UserId = currentUser.Id,
            Username = currentUser.Username
        );

        TrxSec_DetectReportExportsByProfile policy = new TrxSec_DetectReportExportsByProfile();

        System.assertEquals(
            false,
            policy.evaluate((SObject)testEvent),
            'ReportRunFromLightning is not an export and must not trigger the policy'
        );
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
        
        // Operation is nillable. The old guard was accidentally null-safe because
        // 'ReportExported'.equals(null) is false; a prefix match on a null value would throw a
        // NullPointerException instead. An exception escaping a TSP condition has unpredictable
        // enforcement consequences, so assert explicitly that nothing is thrown.
        for (String blankOperation : new List<String>{ null, '' }) {
            ReportEvent blankOpEvent = new ReportEvent(
                Operation = blankOperation,
                UserId = currentUser.Id,
                Username = currentUser.Username
            );
            try {
                System.assertEquals(false, policy.evaluate((SObject)blankOpEvent),
                    'A blank Operation should not trigger policy. Operation: ' + blankOperation);
            } catch (Exception e) {
                System.assert(false,
                    'A blank Operation must not throw out of evaluate(). Operation: ' +
                        blankOperation + ', exception: ' + e.getTypeName() + ' - ' + e.getMessage());
            }
        }
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
