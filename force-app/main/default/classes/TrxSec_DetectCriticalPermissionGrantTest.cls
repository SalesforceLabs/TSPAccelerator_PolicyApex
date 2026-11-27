/**
 * @description Test class for TrxSec_DetectCriticalPermissionGrant
 */
@isTest
private class TrxSec_DetectCriticalPermissionGrantTest {

    private static final Id TRUSTED_USER_ID = '005000000000001AAA';
    private static final Id OTHER_USER_ID = '005000000000002AAA';

    private static PermissionSetEventStore buildEvent(String operation, Id userId, String permissionList) {
        PermissionSetEventStore evt = new PermissionSetEventStore();
        evt.Operation = operation;
        evt.UserId = userId;
        evt.PermissionList = permissionList;
        return evt;
    }

    private static void configure(Set<String> ignored, Boolean excludeTrustedUser) {
        TrxSec_DetectCriticalPermissionGrant.ignoredPermissions = ignored;
        TrxSec_PolicyExclusions.overridesForTest = excludeTrustedUser
            ? new List<Policy_Exclusion__mdt>{
                new Policy_Exclusion__mdt(
                    User_ID__c = String.valueOf(TRUSTED_USER_ID),
                    Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_CRITICAL_PERMISSION_GRANT
                )
            }
            : new List<Policy_Exclusion__mdt>();
    }

    @isTest
    static void testDetectsAssignmentByNonExcludedUser() {
        configure(new Set<String>(), true);

        System.assertEquals(true,
            new TrxSec_DetectCriticalPermissionGrant().evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, '["ModifyAllData"]')),
            'Assignment of critical permissions by a non excluded user should trigger');
    }

    @isTest
    static void testCoversPermissionsNotKnownInAdvance() {
        configure(new Set<String>(), false);

        System.assertEquals(true,
            new TrxSec_DetectCriticalPermissionGrant().evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, '["BrandNewPermission2030"]')),
            'A critical permission added by the product later must still trigger');
    }

    @isTest
    static void testIgnoresExcludedUser() {
        configure(new Set<String>(), true);

        System.assertEquals(false,
            new TrxSec_DetectCriticalPermissionGrant().evaluate(buildEvent('AssignedToUsers', TRUSTED_USER_ID, '["ModifyAllData"]')),
            'A user excluded for this policy should not trigger');
    }

    @isTest
    static void testIgnoresOtherOperations() {
        configure(new Set<String>(), false);
        TrxSec_DetectCriticalPermissionGrant policy = new TrxSec_DetectCriticalPermissionGrant();

        System.assertEquals(false, policy.evaluate(buildEvent('PermsEnabled', OTHER_USER_ID, '["ModifyAllData"]')), 'Permission enabled');
        System.assertEquals(false, policy.evaluate(buildEvent('PermsDisabled', OTHER_USER_ID, '["ModifyAllData"]')), 'Permission disabled');
        System.assertEquals(false, policy.evaluate(buildEvent(null, OTHER_USER_ID, '["ModifyAllData"]')), 'Blank operation');
    }

    @isTest
    static void testIgnoredPermissionsStaySilent() {
        configure(new Set<String>{ 'viewsetup', 'ApiEnabled' }, false);
        TrxSec_DetectCriticalPermissionGrant policy = new TrxSec_DetectCriticalPermissionGrant();

        System.assertEquals(false, policy.evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, '["ViewSetup","apienabled"]')),
            'Only ignored permissions, case insensitive, should stay silent');
        System.assertEquals(true, policy.evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, '["ViewSetup","ModifyAllData"]')),
            'One permission outside the ignore list should trigger');
    }

    @isTest
    static void testUnreadablePermissionListFailsClosed() {
        configure(new Set<String>{ 'ViewSetup' }, false);
        TrxSec_DetectCriticalPermissionGrant policy = new TrxSec_DetectCriticalPermissionGrant();

        System.assertEquals(true, policy.evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, null)), 'Blank list');
        System.assertEquals(true, policy.evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, 'not json')), 'Unreadable list');
        System.assertEquals(true, policy.evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, '[]')), 'Empty list');
        System.assertEquals(true, policy.evaluate(buildEvent('AssignedToUsers', OTHER_USER_ID, '[{"a":1}]')), 'Unexpected shape');
    }

    @isTest
    static void testHandlesNullAndUnsupportedEvent() {
        configure(new Set<String>(), false);
        TrxSec_DetectCriticalPermissionGrant policy = new TrxSec_DetectCriticalPermissionGrant();

        System.assertEquals(false, policy.evaluate(null), 'Null event should not trigger');
        System.assertEquals(false, policy.evaluate(new ApiEvent()), 'Unhandled event type should not trigger');
    }
}
