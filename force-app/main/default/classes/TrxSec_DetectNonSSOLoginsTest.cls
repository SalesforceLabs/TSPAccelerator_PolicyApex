/**
 * @description Test class for TrxSec_DetectNonSSOLogins
 */
@isTest
private class TrxSec_DetectNonSSOLoginsTest {
    
    /**
     * Test that a standard user login with Application type triggers the policy
     * This is the case we want to detect - non-SSO logins
     */
    @isTest
    static void testStandardUserApplicationLogin() {
        // Create a LoginEvent with LoginType='Application' and UserType='Standard'
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Evaluate the policy
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return true (this is a non-SSO login that should be flagged)
        System.assertEquals(true, result, 'Standard user with Application login type should trigger policy');
    }
    
    /**
     * Test that an SSO login does not trigger the policy
     */
    @isTest
    static void testSSOLogin() {
        // Create a LoginEvent with LoginType='SAML Sfdc Initiated SSO' and UserType='Standard'
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'SAML Sfdc Initiated SSO',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Evaluate the policy
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (SSO login should not trigger policy)
        System.assertEquals(false, result, 'SSO login should not trigger policy');
    }
    
    /**
     * Test that a guest user login does not trigger the policy
     */
    @isTest
    static void testGuestUserLogin() {
        // Create a LoginEvent with LoginType='Application' but UserType='Guest'
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserType = 'Guest',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Evaluate the policy
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (guest users should not trigger policy)
        System.assertEquals(false, result, 'Guest user login should not trigger policy');
    }
    
    /**
     * Test that a service user login does not trigger the policy
     */
    @isTest
    static void testServiceUserLogin() {
        // Create a LoginEvent with LoginType='Application' but UserType='Automated Process'
        LoginEvent testEvent = new LoginEvent(
            LoginType = 'Application',
            UserType = 'Automated Process',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Evaluate the policy
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (automated process users should not trigger policy)
        System.assertEquals(false, result, 'Automated process user login should not trigger policy');
    }
    
    /**
     * Test various LoginType values
     */
    @isTest
    static void testVariousLoginTypes() {
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        
        // Test OAuth login
        LoginEvent oauthEvent = new LoginEvent(
            LoginType = 'OAuth',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)oauthEvent), 'OAuth login should not trigger policy');
        
        // Test Remote Access login
        LoginEvent remoteEvent = new LoginEvent(
            LoginType = 'Remote Access',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)remoteEvent), 'Remote Access login should not trigger policy');
        
        // Test Certificate-based login
        LoginEvent certEvent = new LoginEvent(
            LoginType = 'Certificate Based',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)certEvent), 'Certificate-based login should not trigger policy');
    }
    
    /**
     * Test that null event returns false
     */
    @isTest
    static void testNullEvent() {
        // Evaluate the policy with null event
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        Boolean result = policy.evaluate((SObject)null);
        
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
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (non-LoginEvent should not trigger policy)
        System.assertEquals(false, result, 'Non-LoginEvent should not trigger policy');
    }
    
    /**
     * Test case sensitivity of field values
     */
    @isTest
    static void testCaseSensitivity() {
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        
        // Test with lowercase 'application'
        LoginEvent lowercaseEvent = new LoginEvent(
            LoginType = 'application',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)lowercaseEvent), 
            'Lowercase "application" should not match due to case sensitivity');
        
        // Test with lowercase 'standard'
        LoginEvent lowercaseUserType = new LoginEvent(
            LoginType = 'Application',
            UserType = 'standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)lowercaseUserType), 
            'Lowercase "standard" should not match due to case sensitivity');
    }
    
    /**
     * Test with blank or null field values
     */
    @isTest
    static void testBlankOrNullFields() {
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        
        // Test with null LoginType
        LoginEvent nullLoginType = new LoginEvent(
            LoginType = null,
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)nullLoginType), 
            'Null LoginType should not trigger policy');
        
        // Test with null UserType
        LoginEvent nullUserType = new LoginEvent(
            LoginType = 'Application',
            UserType = null,
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)nullUserType), 
            'Null UserType should not trigger policy');
        
        // Test with both null
        LoginEvent bothNull = new LoginEvent(
            LoginType = null,
            UserType = null,
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        System.assertEquals(false, policy.evaluate((SObject)bothNull), 
            'Both null fields should not trigger policy');
    }
    
    /**
     * Test multiple evaluations to ensure consistency
     */
    @isTest
    static void testMultipleEvaluations() {
        TrxSec_DetectNonSSOLogins policy = new TrxSec_DetectNonSSOLogins();
        
        // Create a test event that should trigger
        LoginEvent triggerEvent = new LoginEvent(
            LoginType = 'Application',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Create a test event that should not trigger
        LoginEvent noTriggerEvent = new LoginEvent(
            LoginType = 'SAML Sfdc Initiated SSO',
            UserType = 'Standard',
            UserId = UserInfo.getUserId(),
            Username = UserInfo.getUserName()
        );
        
        // Evaluate multiple times to ensure consistent results
        for (Integer i = 0; i < 5; i++) {
            System.assertEquals(true, policy.evaluate((SObject)triggerEvent), 
                'Multiple evaluations should return consistent results (true)');
            System.assertEquals(false, policy.evaluate((SObject)noTriggerEvent), 
                'Multiple evaluations should return consistent results (false)');
        }
    }
}

