/**
 * @description Test class for TrxSec_DetectLoginAsEvent
 */
@isTest
private class TrxSec_DetectLoginAsEventTest {

    @isTest
    static void testDetectsLoginAsEvent() {
        LoginAsEvent testEvent = new LoginAsEvent();

        Boolean result = new TrxSec_DetectLoginAsEvent().evaluate(testEvent);
        System.assertEquals(true, result, 'Should detect all LoginAsEvent occurrences');
    }

    @isTest
    static void testAlwaysReturnsTrueForLoginAsEvent() {
        // Create multiple LoginAsEvent instances to verify consistent behavior
        LoginAsEvent testEvent1 = new LoginAsEvent();
        LoginAsEvent testEvent2 = new LoginAsEvent();

        TrxSec_DetectLoginAsEvent policy = new TrxSec_DetectLoginAsEvent();
        
        Boolean result1 = policy.evaluate(testEvent1);
        Boolean result2 = policy.evaluate(testEvent2);
        
        System.assertEquals(true, result1, 'Should always return true for LoginAsEvent');
        System.assertEquals(true, result2, 'Should always return true for LoginAsEvent');
    }

    @isTest
    static void testMultipleInvocations() {
        LoginAsEvent testEvent = new LoginAsEvent();
        TrxSec_DetectLoginAsEvent policy = new TrxSec_DetectLoginAsEvent();

        // Test multiple invocations of the same policy instance
        for (Integer i = 0; i < 5; i++) {
            Boolean result = policy.evaluate(testEvent);
            System.assertEquals(true, result, 'Should consistently return true on iteration ' + i);
        }
    }
}
