/**
 * @description Test class for TrxSec_DetectTLSCipherSuiteLogin
 */
@isTest
private class TrxSec_DetectTLSCipherSuiteLoginTest {
    
    /**
     * Helper method to mock the allowed cipher suites configuration
     */
    private static void mockAllowedCipherSuites(Set<String> suites) {
        TrxSec_DetectTLSCipherSuiteLogin.allowedSuites = suites;
    }

    /**
     * Test that a login with a cipher suite in the allowed list does not trigger the policy
     */
    @isTest
    static void testAllowedCipherSuite() {
        // Mock configuration
        String allowedSuite = 'TLS_AES_256_GCM_SHA384';
        mockAllowedCipherSuites(new Set<String>{allowedSuite});
        
        // Create a LoginEvent with an allowed cipher suite
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = Datetime.now();
        testEvent.CipherSuite = allowedSuite;
        
        // Evaluate the policy
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (allowed cipher suite, no alert)
        System.assertEquals(false, result, 'Login with allowed cipher suite should not trigger policy');
    }
    
    /**
     * Test that a login with a cipher suite NOT in the allowed list triggers the policy
     */
    @isTest
    static void testDisallowedCipherSuite() {
        // Mock configuration
        mockAllowedCipherSuites(new Set<String>{'TLS_AES_256_GCM_SHA384'});

        // Create a LoginEvent with a disallowed cipher suite
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = Datetime.now();
        testEvent.CipherSuite = 'WEAK_CIPHER_SUITE_NOT_IN_CMT';
        
        // Evaluate the policy
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return true (disallowed cipher suite, triggers alert)
        System.assertEquals(true, result, 'Login with disallowed cipher suite should trigger policy');
    }
    
    /**
     * Test that a login with a blank cipher suite does not trigger the policy
     */
    @isTest
    static void testBlankCipherSuite() {
        // Mock configuration
        mockAllowedCipherSuites(new Set<String>{'TLS_AES_256_GCM_SHA384'});

        // Create a LoginEvent with blank cipher suite
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = Datetime.now();
        testEvent.CipherSuite = '';
        
        // Evaluate the policy
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (blank cipher suite is ignored)
        System.assertEquals(false, result, 'Login with blank cipher suite should not trigger policy');
    }
    
    /**
     * Test that a login with a null cipher suite does not trigger the policy
     */
    @isTest
    static void testNullCipherSuite() {
        // Mock configuration
        mockAllowedCipherSuites(new Set<String>{'TLS_AES_256_GCM_SHA384'});

        // Create a LoginEvent with null cipher suite
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = Datetime.now();
        testEvent.CipherSuite = null;
        
        // Evaluate the policy
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return false (null cipher suite is ignored)
        System.assertEquals(false, result, 'Login with null cipher suite should not trigger policy');
    }
    
    /**
     * Test that a non-LoginEvent SObject returns false
     */
    @isTest
    static void testNonLoginEvent() {
        // Evaluate the policy with non-LoginEvent
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate(new Account(Name = 'Test'));
        
        // Should return false (not a LoginEvent)
        System.assertEquals(false, result, 'Non-LoginEvent should not trigger policy');
    }
    
    /**
     * Test that null event returns false
     */
    @isTest
    static void testNullEvent() {
        // Evaluate the policy with null event
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)null);
        
        // Should return false (null event is handled by switch statement)
        System.assertEquals(false, result, 'Null event should not trigger policy');
    }
    
    /**
     * Test case sensitivity of cipher suite comparison
     */
    @isTest
    static void testCaseSensitiveCipherSuite() {
        // Mock configuration
        String allowedSuite = 'TLS_AES_256_GCM_SHA384';
        mockAllowedCipherSuites(new Set<String>{allowedSuite});
        
        // Create a LoginEvent with lowercase cipher suite
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = Datetime.now();
        testEvent.CipherSuite = allowedSuite.toLowerCase();
        
        // Evaluate the policy
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should be case sensitive (so it should trigger as true because lowercase doesn't match uppercase allowed suite)
        // This aligns with previous test behavior
        System.assertEquals(true, result, 'Should detect case differences in cipher suite names');
    }
    
    /**
     * Test with no allowed cipher suites (empty list)
     */
    @isTest
    static void testNoAllowedSuites() {
        // Mock empty configuration
        mockAllowedCipherSuites(new Set<String>());
        
        // Create a LoginEvent with any cipher suite
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = Datetime.now();
        testEvent.CipherSuite = 'TLS_AES_256_GCM_SHA384';
        
        // Evaluate the policy
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return true (blocked because nothing is allowed)
        System.assertEquals(true, result, 'Should trigger policy when no suites are allowed');
    }
    
    /**
     * Test with multiple allowed cipher suites
     */
    @isTest
    static void testMultipleAllowedCipherSuites() {
        // Mock configuration
        Set<String> allowed = new Set<String>{
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256'
        };
        mockAllowedCipherSuites(allowed);
        
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        
        // Test first allowed suite
        LoginEvent event1 = new LoginEvent();
        event1.CipherSuite = 'TLS_AES_256_GCM_SHA384';
        System.assertEquals(false, policy.evaluate((SObject)event1), 'First suite should be allowed');
        
        // Test second allowed suite
        LoginEvent event2 = new LoginEvent();
        event2.CipherSuite = 'TLS_CHACHA20_POLY1305_SHA256';
        System.assertEquals(false, policy.evaluate((SObject)event2), 'Second suite should be allowed');
        
        // Test disallowed suite
        LoginEvent event3 = new LoginEvent();
        event3.CipherSuite = 'WEAK_SUITE';
        System.assertEquals(true, policy.evaluate((SObject)event3), 'Other suite should be blocked');
    }
    
    /**
     * Test caching behavior
     */
    @isTest
    static void testCachingBehavior() {
        // Initial mock
        mockAllowedCipherSuites(new Set<String>{'SuiteA'});
        
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        
        // Verify initial state
        LoginEvent event = new LoginEvent();
        event.CipherSuite = 'SuiteA';
        System.assertEquals(false, policy.evaluate((SObject)event), 'SuiteA should be allowed initially');
        
        // Update mock "cache"
        mockAllowedCipherSuites(new Set<String>{'SuiteB'});
        
        // Verify new state
        event.CipherSuite = 'SuiteB';
        System.assertEquals(false, policy.evaluate((SObject)event), 'SuiteB should be allowed after update');
        
        event.CipherSuite = 'SuiteA';
        System.assertEquals(true, policy.evaluate((SObject)event), 'SuiteA should be blocked after update');
    }
    
    /**
     * Test with whitespace in cipher suite
     */
    @isTest
    static void testCipherSuiteWithWhitespace() {
        // Mock configuration
        mockAllowedCipherSuites(new Set<String>{'TLS_AES_256_GCM_SHA384'});
        
        // Create a LoginEvent with cipher suite containing whitespace
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = Datetime.now();
        testEvent.CipherSuite = ' TLS_AES_256_GCM_SHA384 ';
        
        // Evaluate the policy
        TrxSec_DetectTLSCipherSuiteLogin policy = new TrxSec_DetectTLSCipherSuiteLogin();
        Boolean result = policy.evaluate((SObject)testEvent);
        
        // Should return true (blocked) because of exact match requirement against "TLS_AES_256_GCM_SHA384"
        System.assertEquals(true, result, 'Should handle cipher suite with whitespace as distinct value');
    }
}
