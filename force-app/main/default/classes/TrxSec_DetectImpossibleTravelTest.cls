/**
 * @description Test class for TrxSec_DetectImpossibleTravel
 * Note: LoginHistory is a standard object that cannot be directly inserted in test context.
 * These tests verify the policy's behavior when no previous login history exists,
 * and test the null-safety and edge case handling of the evaluate method.
 */
@isTest
private class TrxSec_DetectImpossibleTravelTest {

    private class StubProvider implements TrxSec_DetectImpossibleTravel.Provider {
        private final TrxSec_DetectImpossibleTravel.LoginSnapshot snapshot;
        private final Boolean shouldThrow;

        StubProvider(TrxSec_DetectImpossibleTravel.LoginSnapshot snapshot) {
            this.snapshot = snapshot;
            this.shouldThrow = false;
        }

        StubProvider(Boolean shouldThrow) {
            this.snapshot = null;
            this.shouldThrow = shouldThrow;
        }

        public TrxSec_DetectImpossibleTravel.LoginSnapshot getMostRecentLogin(Id userId) {
            if (shouldThrow == true) {
                throw new TestProviderException('boom');
            }
            return snapshot;
        }
    }

    private class TestProviderException extends Exception {}

    private static void useProvider(TrxSec_DetectImpossibleTravel.LoginSnapshot snapshot) {
        TrxSec_DetectImpossibleTravel.provider = new StubProvider(snapshot);
    }

    private static void useThrowingProvider() {
        TrxSec_DetectImpossibleTravel.provider = new StubProvider(true);
    }

    private static LoginEvent buildEvent(DateTime eventDate, String city, String countryIso) {
        LoginEvent e = new LoginEvent();
        e.UserId = UserInfo.getUserId();
        e.EventDate = eventDate;
        e.City = city;
        e.CountryIso = countryIso;
        return e;
    }
    
    /**
     * Test that first login (no previous login history) returns false
     * This is the typical test scenario since LoginHistory cannot be inserted
     */
    @isTest
    static void testFirstLogin_NoPreviousHistory() {
        useProvider(null);

        LoginEvent testEvent = buildEvent(Datetime.now(), 'New York', 'US');
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false (no previous login to compare)
        System.assertEquals(false, result, 'First login should not trigger impossible travel alert');
    }
    
    /**
     * Test that null LoginEvent returns false
     */
    @isTest
    static void testNullEvent() {
        // Evaluate the policy with null event
        Test.startTest();
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        Boolean result = policy.evaluate(null);
        Test.stopTest();
        
        // Should return false (safe handling of null)
        System.assertEquals(false, result, 'Null event should not trigger impossible travel alert');
    }
    
    /**
     * Test that LoginEvent with null UserId returns false
     */
    @isTest
    static void testNullUserId() {
        useProvider(null);

        // Create a LoginEvent with null UserId
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = null;
        testEvent.EventDate = Datetime.now();
        testEvent.City = 'New York';
        testEvent.CountryIso = 'US';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false (safe handling of null UserId)
        System.assertEquals(false, result, 'Event with null UserId should not trigger impossible travel alert');
    }
    
    /**
     * Test that LoginEvent with null EventDate returns false
     */
    @isTest
    static void testNullEventDate() {
        useProvider(null);
        
        // Create a LoginEvent with null EventDate
        LoginEvent testEvent = new LoginEvent();
        testEvent.UserId = UserInfo.getUserId();
        testEvent.EventDate = null;
        testEvent.City = 'New York';
        testEvent.CountryIso = 'US';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false (safe handling of null EventDate)
        System.assertEquals(false, result, 'Event with null EventDate should not trigger impossible travel alert');
    }
    
    /**
     * Test with various user IDs to ensure no errors
     * LoginHistory query will return empty list for all users in test context
     */
    @isTest
    static void testMultipleUsers() {
        useProvider(null);

        Test.startTest();
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        
        LoginEvent testEvent = buildEvent(Datetime.now(), 'San Francisco', 'US');
        Boolean result = policy.evaluate(testEvent);

        // Should return false (no previous login history)
        System.assertEquals(false, result, 'Should not trigger alert without login history');

        Test.stopTest();
    }
    
    /**
     * Test with null City in LoginEvent
     */
    @isTest
    static void testNullCity() {
        useProvider(null);

        LoginEvent testEvent = buildEvent(Datetime.now(), null, 'US');
        
        Test.startTest();
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false (no previous login history)
        System.assertEquals(false, result, 'Should handle null city gracefully');
    }
    
    /**
     * Test with null CountryIso in LoginEvent
     */
    @isTest
    static void testNullCountryIso() {
        useProvider(null);

        LoginEvent testEvent = buildEvent(Datetime.now(), 'Paris', null);
        
        Test.startTest();
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false (no previous login history)
        System.assertEquals(false, result, 'Should handle null country gracefully');
    }
    
    /**
     * Test that verifies query structure and permissions
     * This ensures the query compiles and runs without errors
     */
    @isTest
    static void testLoginHistoryQueryExecution() {
        // Cover DefaultProvider path; result may be null in a clean org
        TrxSec_DetectImpossibleTravel.resetProviderForTest();
        Test.startTest();
        TrxSec_DetectImpossibleTravel.LoginSnapshot last = TrxSec_DetectImpossibleTravel.provider.getMostRecentLogin(UserInfo.getUserId());
        Test.stopTest();
        System.assertEquals(true, (last == null || last.loginTime != null), 'Default provider should execute without throwing');
    }
    
    /**
     * Test with various location data combinations
     */
    @isTest
    static void testVariousLocationCombinations() {
        TrxSec_DetectImpossibleTravel policy = new TrxSec_DetectImpossibleTravel();
        
        // Test Case 1: Both city and country provided
        useProvider(null);
        LoginEvent event1 = buildEvent(Datetime.now(), 'Tokyo', 'JP');
        
        // Test Case 2: Empty strings instead of null
        LoginEvent event2 = buildEvent(Datetime.now(), '', '');
        
        Test.startTest();
        
        Boolean result1 = policy.evaluate(event1);
        Boolean result2 = policy.evaluate(event2);
        
        Test.stopTest();
        
        // Both should return false (no previous login history)
        System.assertEquals(false, result1, 'Should handle normal location data');
        System.assertEquals(false, result2, 'Should handle empty string location data');
    }

    @isTest
    static void testWithin30MinsCityChangedReturnsTrue() {
        DateTime nowTime = DateTime.now();
        useProvider(new TrxSec_DetectImpossibleTravel.LoginSnapshot(nowTime.addMinutes(-10), 'US', 'Chicago'));
        Boolean result = new TrxSec_DetectImpossibleTravel().evaluate(buildEvent(nowTime, 'New York', 'US'));
        System.assertEquals(true, result, 'City change within 30 mins should trigger');
    }

    @isTest
    static void testWithin30MinsCountryChangedReturnsTrue() {
        DateTime nowTime = DateTime.now();
        useProvider(new TrxSec_DetectImpossibleTravel.LoginSnapshot(nowTime.addMinutes(-10), 'US', 'New York'));
        Boolean result = new TrxSec_DetectImpossibleTravel().evaluate(buildEvent(nowTime, 'New York', 'CA'));
        System.assertEquals(true, result, 'Country change within 30 mins should trigger');
    }

    @isTest
    static void testWithin30MinsNoChangesReturnsFalse() {
        DateTime nowTime = DateTime.now();
        useProvider(new TrxSec_DetectImpossibleTravel.LoginSnapshot(nowTime.addMinutes(-10), 'US', 'New York'));
        Boolean result = new TrxSec_DetectImpossibleTravel().evaluate(buildEvent(nowTime, 'New York', 'US'));
        System.assertEquals(false, result, 'No change within 30 mins should not trigger');
    }

    @isTest
    static void testOutside30MinsReturnsFalse() {
        DateTime nowTime = DateTime.now();
        useProvider(new TrxSec_DetectImpossibleTravel.LoginSnapshot(nowTime.addMinutes(-31), 'US', 'Chicago'));
        Boolean result = new TrxSec_DetectImpossibleTravel().evaluate(buildEvent(nowTime, 'New York', 'CA'));
        System.assertEquals(false, result, 'Outside 30 mins should not trigger');
    }

    @isTest
    static void testProviderExceptionHandledReturnsFalse() {
        useThrowingProvider();
        Boolean result = new TrxSec_DetectImpossibleTravel().evaluate(buildEvent(DateTime.now(), 'New York', 'US'));
        System.assertEquals(false, result, 'Provider exceptions should be handled and return false');
    }
}
