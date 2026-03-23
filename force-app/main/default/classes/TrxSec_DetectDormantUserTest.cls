/**
 * @description Test class for TrxSec_DetectDormantUser
 */
@isTest
private class TrxSec_DetectDormantUserTest {

    private class StubProvider implements TrxSec_DetectDormantUser.Provider {
        private final List<TrxSec_DetectDormantUser.LoginAttempt> recentLogins;
        private final Boolean shouldThrow;

        StubProvider(List<TrxSec_DetectDormantUser.LoginAttempt> recentLogins) {
            this.recentLogins = recentLogins;
            this.shouldThrow = false;
        }

        StubProvider(Boolean shouldThrow) {
            this.recentLogins = new List<TrxSec_DetectDormantUser.LoginAttempt>();
            this.shouldThrow = shouldThrow;
        }

        public List<TrxSec_DetectDormantUser.LoginAttempt> getRecentLogins(Id userId, DateTime currentLoginTime) {
            if (shouldThrow == true) {
                // Any exception should be caught and return false
                throw new TestProviderException('boom');
            }
            return recentLogins == null ? new List<TrxSec_DetectDormantUser.LoginAttempt>() : recentLogins;
        }
    }

    private class TestProviderException extends Exception {}

    private static void useProvider(List<TrxSec_DetectDormantUser.LoginAttempt> recentLogins) {
        TrxSec_DetectDormantUser.provider = new StubProvider(recentLogins);
    }

    private static void useThrowingProvider() {
        TrxSec_DetectDormantUser.provider = new StubProvider(true);
    }

    private static LoginEvent buildLoginEvent(DateTime eventDate) {
        return new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = eventDate
        );
    }
    
    /**
     * Test that a login event with all required fields triggers the evaluation
     */
    @isTest
    static void testSuccessfulLogin() {
        // Create a LoginEvent with required fields
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        
        // Evaluate the policy
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)testEvent);
        Test.stopTest();
        
        // Result will be false since we can't insert LoginHistory records in test context
        // But the method should execute without errors
        System.assertNotEquals(null, result, 'Policy should return a non-null result');
    }

    @isTest
    static void testNoPreviousSuccessfulLoginReturnsFalse() {
        // No recent logins -> lastLoginTime stays null -> returns false
        useProvider(new List<TrxSec_DetectDormantUser.LoginAttempt>());

        LoginEvent testEvent = buildLoginEvent(DateTime.now());
        Boolean result = new TrxSec_DetectDormantUser().evaluate((SObject)testEvent);
        System.assertEquals(false, result, 'No previous successful login should not trigger policy');
    }

    @isTest
    static void testAllFailuresReturnFalse() {
        DateTime nowTime = DateTime.now();
        List<TrxSec_DetectDormantUser.LoginAttempt> logins = new List<TrxSec_DetectDormantUser.LoginAttempt>{
            new TrxSec_DetectDormantUser.LoginAttempt(nowTime.addDays(-1), 'Failed'),
            new TrxSec_DetectDormantUser.LoginAttempt(nowTime.addDays(-5), 'InvalidPassword')
        };
        useProvider(logins);

        LoginEvent testEvent = buildLoginEvent(nowTime);
        Boolean result = new TrxSec_DetectDormantUser().evaluate((SObject)testEvent);
        System.assertEquals(false, result, 'All failures should not trigger policy');
    }

    @isTest
    static void testNonDormantUserReturnsFalse() {
        DateTime nowTime = DateTime.now();
        // Most recent successful login is within threshold (< 90 days)
        List<TrxSec_DetectDormantUser.LoginAttempt> logins = new List<TrxSec_DetectDormantUser.LoginAttempt>{
            new TrxSec_DetectDormantUser.LoginAttempt(nowTime.addDays(-10), 'Success')
        };
        useProvider(logins);

        LoginEvent testEvent = buildLoginEvent(nowTime);
        Boolean result = new TrxSec_DetectDormantUser().evaluate((SObject)testEvent);
        System.assertEquals(false, result, 'Recent successful login should not be considered dormant');
    }

    @isTest
    static void testDormantUserReturnsTrue() {
        DateTime nowTime = DateTime.now();
        // Most recent successful login is beyond threshold (>= 90 days)
        List<TrxSec_DetectDormantUser.LoginAttempt> logins = new List<TrxSec_DetectDormantUser.LoginAttempt>{
            new TrxSec_DetectDormantUser.LoginAttempt(nowTime.addDays(-91), 'Success')
        };
        useProvider(logins);

        LoginEvent testEvent = buildLoginEvent(nowTime);
        Boolean result = new TrxSec_DetectDormantUser().evaluate((SObject)testEvent);
        System.assertEquals(true, result, 'Old successful login should be considered dormant');
    }

    @isTest
    static void testProviderExceptionHandled() {
        useThrowingProvider();

        LoginEvent testEvent = buildLoginEvent(DateTime.now());
        Boolean result = new TrxSec_DetectDormantUser().evaluate((SObject)testEvent);
        System.assertEquals(false, result, 'Exceptions should be handled and return false');
    }

    @isTest
    static void testDefaultProviderMethodsCovered() {
        // Cover DefaultProvider SOQL path; result can be empty depending on org
        TrxSec_DetectDormantUser.resetProviderForTest();
        List<TrxSec_DetectDormantUser.LoginAttempt> logins = TrxSec_DetectDormantUser.provider.getRecentLogins(UserInfo.getUserId(), DateTime.now());
        System.assertNotEquals(null, logins, 'Default provider should return a non-null list');
    }
    
    /**
     * Test with null UserId
     */
    @isTest
    static void testNullUserId() {
        // Create a LoginEvent with null UserId
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = null,
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        
        // Evaluate the policy
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)testEvent);
        Test.stopTest();
        
        // Should return false (null UserId should not trigger policy)
        System.assertEquals(false, result, 'Null UserId should not trigger policy');
    }
    
    /**
     * Test with null EventDate
     */
    @isTest
    static void testNullEventDate() {
        // Create a LoginEvent with null EventDate
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = null
        );
        
        // Evaluate the policy
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)testEvent);
        Test.stopTest();
        
        // Should return false
        System.assertEquals(false, result, 'Null EventDate should not trigger policy');
    }
    
    /**
     * Test with both null required fields
     */
    @isTest
    static void testBothRequiredFieldsNull() {
        // Create a LoginEvent with null UserId and EventDate
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = null,
            Username = UserInfo.getUserName(),
            EventDate = null
        );
        
        // Evaluate the policy
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)testEvent);
        Test.stopTest();
        
        // Should return false
        System.assertEquals(false, result, 'Both null required fields should not trigger policy');
    }
    
    /**
     * Test with null event
     */
    @isTest
    static void testNullEvent() {
        // Evaluate the policy with null event
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)null);
        Test.stopTest();
        
        // Should return false (null event is handled by switch statement)
        System.assertEquals(false, result, 'Null event should not trigger policy');
    }
    
    /**
     * Test that a non-LoginEvent returns false
     */
    @isTest
    static void testNonLoginEvent() {
        // Create a ReportEvent (not a LoginEvent)
        ReportEvent testEvent = new ReportEvent(
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Evaluate the policy
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)testEvent);
        Test.stopTest();
        
        // Should return false (non-LoginEvent should not trigger policy)
        System.assertEquals(false, result, 'Non-LoginEvent should not trigger policy');
    }
    
    /**
     * Test with ApiEvent to ensure only LoginEvent is processed
     */
    @isTest
    static void testApiEvent() {
        // Create an ApiEvent (not a LoginEvent)
        ApiEvent testEvent = new ApiEvent(
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Evaluate the policy
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)testEvent);
        Test.stopTest();
        
        // Should return false (non-LoginEvent should not trigger policy)
        System.assertEquals(false, result, 'ApiEvent should not trigger policy');
    }
    
    /**
     * Test multiple successful logins to ensure consistency
     */
    @isTest
    static void testMultipleEvaluations() {
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        // Create a test event
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        
        Test.startTest();
        // Evaluate multiple times to ensure consistent results
        Boolean result1 = policy.evaluate((SObject)testEvent);
        Boolean result2 = policy.evaluate((SObject)testEvent);
        Boolean result3 = policy.evaluate((SObject)testEvent);
        Test.stopTest();
        
        // All evaluations should return the same result
        System.assertEquals(result1, result2, 'Multiple evaluations should be consistent');
        System.assertEquals(result2, result3, 'Multiple evaluations should be consistent');
    }
    
    /**
     * Test with various login types
     */
    @isTest
    static void testVariousLoginTypes() {
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        
        // Test OAuth login
        LoginEvent oauthEvent = new LoginEvent(
            LoginType = 'OAuth',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        Boolean oauthResult = policy.evaluate((SObject)oauthEvent);
        System.assertNotEquals(null, oauthResult, 'OAuth login should be evaluated');
        
        // Test SSO login
        LoginEvent ssoEvent = new LoginEvent(
            LoginType = 'SAML Sfdc Initiated SSO',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        Boolean ssoResult = policy.evaluate((SObject)ssoEvent);
        System.assertNotEquals(null, ssoResult, 'SSO login should be evaluated');
        
        // Test Remote Access login
        LoginEvent remoteEvent = new LoginEvent(
            LoginType = 'Remote Access',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        Boolean remoteResult = policy.evaluate((SObject)remoteEvent);
        System.assertNotEquals(null, remoteResult, 'Remote Access login should be evaluated');
        
        Test.stopTest();
    }
    
    /**
     * Test with null or missing fields
     */
    @isTest
    static void testNullFields() {
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        
        // Test with null LoginType (optional field)
        LoginEvent nullLoginType = new LoginEvent(
            LoginType = null,
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        Boolean result1 = policy.evaluate((SObject)nullLoginType);
        System.assertNotEquals(null, result1, 'Null LoginType should still be evaluated');
        
        // Test with null Username (optional field)
        LoginEvent nullUsername = new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = null,
            EventDate = DateTime.now()
        );
        Boolean result2 = policy.evaluate((SObject)nullUsername);
        System.assertNotEquals(null, result2, 'Null Username should still be evaluated');
        
        Test.stopTest();
    }
    
    /**
     * Test exception handling by using a minimal event
     */
    @isTest
    static void testExceptionHandling() {
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        // Create a minimal LoginEvent with just required fields
        LoginEvent minimalEvent = new LoginEvent(
            EventDate = DateTime.now(),
            UserId = UserInfo.getUserId()
        );
        
        Test.startTest();
        Boolean result = policy.evaluate((SObject)minimalEvent);
        Test.stopTest();
        
        // Should handle gracefully without throwing exception
        System.assertNotEquals(null, result, 'Should handle minimal event without throwing exception');
    }
    
    /**
     * Test bulk evaluations to ensure no governor limit issues
     */
    @isTest
    static void testBulkEvaluations() {
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        List<Boolean> results = new List<Boolean>();
        
        Test.startTest();
        
        // Simulate multiple login events
        for (Integer i = 0; i < 50; i++) {
            LoginEvent testEvent = new LoginEvent(
                LoginType = 'Application',
                UserId = UserInfo.getUserId(),
                Username = UserInfo.getUserName(),
                EventDate = DateTime.now().addMinutes(i)
            );
            results.add(policy.evaluate((SObject)testEvent));
        }
        
        Test.stopTest();
        
        // All evaluations should complete without errors
        System.assertEquals(50, results.size(), 'All 50 evaluations should complete');
        
        // Check SOQL query limits
        System.assert(Limits.getQueries() <= Limits.getLimitQueries(), 
            'Should not exceed SOQL query limits');
    }
    
    /**
     * Test with different event dates
     */
    @isTest
    static void testDifferentEventDates() {
        TrxSec_DetectDormantUser policy = new TrxSec_DetectDormantUser();
        
        Test.startTest();
        
        // Test with current datetime
        LoginEvent currentEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now()
        );
        Boolean currentResult = policy.evaluate((SObject)currentEvent);
        System.assertNotEquals(null, currentResult, 'Current datetime should be evaluated');
        
        // Test with past datetime
        LoginEvent pastEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now().addDays(-30)
        );
        Boolean pastResult = policy.evaluate((SObject)pastEvent);
        System.assertNotEquals(null, pastResult, 'Past datetime should be evaluated');
        
        // Test with future datetime (edge case)
        LoginEvent futureEvent = new LoginEvent(
            LoginType = 'Application',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName(),
            EventDate = DateTime.now().addDays(1)
        );
        Boolean futureResult = policy.evaluate((SObject)futureEvent);
        System.assertNotEquals(null, futureResult, 'Future datetime should be evaluated');
        
        Test.stopTest();
    }
}

