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

    @isTest
    static void testExcludedDelegatedAdminDoesNotTrip() {
        Id adminUserId = UserInfo.getUserId();
        User impersonatedUser = insertUser('eximp');
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = adminUserId,
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_LOGIN_AS
            )
        };

        LoginAsEvent testEvent = new LoginAsEvent();
        testEvent.UserId = impersonatedUser.Id;
        testEvent.DelegatedUsername = UserInfo.getUserName();

        Boolean result = new TrxSec_DetectLoginAsEvent().evaluate(testEvent);
        System.assertEquals(
            false,
            result,
            'An excluded administrator (DelegatedUsername) must not trip the Login As policy'
        );
    }

    @isTest
    static void testImpersonatedUserExclusionDoesNotSkip() {
        Id adminUserId = UserInfo.getUserId();
        User impersonatedUser = insertUser('exoth');

        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = impersonatedUser.Id,
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_LOGIN_AS
            )
        };

        LoginAsEvent testEvent = new LoginAsEvent();
        testEvent.UserId = impersonatedUser.Id;
        testEvent.DelegatedUsername = UserInfo.getUserName();

        Boolean result = new TrxSec_DetectLoginAsEvent().evaluate(testEvent);
        System.assertEquals(
            true,
            result,
            'Login As must still trip when only the impersonated UserId is excluded, not the administrator'
        );
        System.assertNotEquals(
            adminUserId,
            impersonatedUser.Id,
            'Test setup must use distinct admin and impersonated users'
        );
    }

    @isTest
    static void testUnknownDelegatedUsernameStillTrips() {
        Id adminUserId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = adminUserId,
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_LOGIN_AS
            )
        };

        LoginAsEvent testEvent = new LoginAsEvent();
        testEvent.UserId = adminUserId;
        testEvent.DelegatedUsername =
            'missing.loginas.admin' + Datetime.now().getTime() + '@testorg.com';

        Boolean result = new TrxSec_DetectLoginAsEvent().evaluate(testEvent);
        System.assertEquals(
            true,
            result,
            'An unresolvable DelegatedUsername must not skip the policy, even if UserId is excluded'
        );
    }

    @isTest
    static void testBlankDelegatedUsernameDoesNotTreatEventUserIdAsAdmin() {
        Id adminUserId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = adminUserId,
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_LOGIN_AS
            )
        };

        LoginAsEvent testEvent = new LoginAsEvent();
        testEvent.UserId = adminUserId;

        Boolean result = new TrxSec_DetectLoginAsEvent().evaluate(testEvent);
        System.assertEquals(
            true,
            result,
            'A blank DelegatedUsername must not fall back to UserId for the exclusion check'
        );
    }

    private static User insertUser(String namePrefix) {
        Profile p = [SELECT Id FROM Profile WHERE Name = 'Standard User' LIMIT 1];
        User otherUser = new User(
            Alias = namePrefix.left(8),
            Email = namePrefix + '@testorg.com',
            EmailEncodingKey = 'UTF-8',
            LastName = 'ExclusionOther',
            LanguageLocaleKey = 'en_US',
            LocaleSidKey = 'en_US',
            ProfileId = p.Id,
            TimeZoneSidKey = 'America/Los_Angeles',
            UserName = namePrefix + Datetime.now().getTime() + '@testorg.com'
        );
        insert otherUser;
        return otherUser;
    }
}
