/**
 * @description Test class for TrxSec_DetectExemptPermissionGrant
 */
@isTest
private class TrxSec_DetectExemptPermissionGrantTest {

    private static final Id EXCLUDED_USER_ID = '005000000000001AAA';

    private static PermissionSetEventStore buildEvent(String operation, String permissionList) {
        PermissionSetEventStore evt = new PermissionSetEventStore();
        evt.Operation = operation;
        evt.PermissionList = permissionList;
        evt.UserId = '005000000000002AAA';
        return evt;
    }

    private static void excludeUser() {
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = String.valueOf(EXCLUDED_USER_ID),
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_EXEMPT_PERMISSION_GRANT
            )
        };
    }

    @isTest
    static void testExcludedUserIsNeverFlagged() {
        excludeUser();
        PermissionSetEventStore evt = buildEvent('PermsEnabled', '["TransactionSecurityExempt"]');
        evt.UserId = EXCLUDED_USER_ID;

        System.assertEquals(false, new TrxSec_DetectExemptPermissionGrant().evaluate(evt),
            'A user excluded for this policy should not trigger');
        evt.UserId = '005000000000002AAA';
        System.assertEquals(true, new TrxSec_DetectExemptPermissionGrant().evaluate(evt),
            'Other users are still flagged');
    }

    @isTest
    static void testBlocksExemptPermissionEnabled() {
        System.assertEquals(true,
            new TrxSec_DetectExemptPermissionGrant().evaluate(buildEvent('PermsEnabled', '["TransactionSecurityExempt"]')),
            'Enabling TransactionSecurityExempt should be blocked');
    }

    @isTest
    static void testBlocksExemptPermissionAssigned() {
        System.assertEquals(true,
            new TrxSec_DetectExemptPermissionGrant().evaluate(buildEvent('AssignedToUsers', '["transactionsecurityexempt","ViewSetup"]')),
            'Assigning a permission set with TransactionSecurityExempt should be blocked, case insensitively');
    }

    @isTest
    static void testAllowsOtherPermissions() {
        System.assertEquals(false,
            new TrxSec_DetectExemptPermissionGrant().evaluate(buildEvent('PermsEnabled', '["ModifyAllData"]')),
            'Other permissions are out of scope for this policy');
    }

    @isTest
    static void testAllowsOtherOperations() {
        System.assertEquals(false,
            new TrxSec_DetectExemptPermissionGrant().evaluate(buildEvent('PermsDisabled', '["TransactionSecurityExempt"]')),
            'Removing the permission should not be blocked');
    }

    @isTest
    static void testHandlesBlankValues() {
        TrxSec_DetectExemptPermissionGrant policy = new TrxSec_DetectExemptPermissionGrant();

        System.assertEquals(false, policy.evaluate(buildEvent(null, '["TransactionSecurityExempt"]')), 'Blank operation');
        System.assertEquals(false, policy.evaluate(buildEvent('PermsEnabled', null)), 'Blank permission list');
    }

    @isTest
    static void testHandlesNullAndUnsupportedEvent() {
        TrxSec_DetectExemptPermissionGrant policy = new TrxSec_DetectExemptPermissionGrant();

        System.assertEquals(false, policy.evaluate(null), 'Null event should not block');
        System.assertEquals(false, policy.evaluate(new ApiEvent()), 'Unhandled event type should not block');
    }
}
