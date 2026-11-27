/**
 * @description Transaction Security Policy condition to detect a permission set or profile
 * carrying a critical permission being assigned to users. Intended as an alert policy on
 * PermissionSetEventStore.
 *
 * Salesforce only raises an AssignedToUsers event when the assigned permission set or profile
 * contains a critical permission, and maintains that list itself. The permissions are therefore
 * deliberately not listed here: new critical permissions added by the product are covered
 * without a code change. Every such assignment triggers unless the assigning user has a
 * Policy_Exclusion__mdt record for this policy (for example the CI/CD user) or every permission
 * in the event is in ignoredPermissions.
 */
global with sharing class TrxSec_DetectCriticalPermissionGrant implements TxnSecurity.EventCondition {

    private static final String ASSIGNED_TO_USERS = 'AssignedToUsers';

    // Permission API names that are acceptable to assign. An assignment only stays silent when
    // every permission it carries is in this set; an empty set ignores nothing. Compared
    // case-insensitively.
    @TestVisible
    private static Set<String> ignoredPermissions = new Set<String>();

    global Boolean evaluate(SObject event) {
        switch on event {
            when PermissionSetEventStore permissionSetEventStore {
                return isViolation(permissionSetEventStore);
            }
            when null {
                // Don't take policy action when event is null
                return false;
            }
            when else {
                // Don't take policy action when event is not handled
                return false;
            }
        }
    }

    private Boolean isViolation(PermissionSetEventStore permissionSetEventStore) {
        // Subscriber-configured exclusions are honored first, so an excluded user can never trip this policy.
        if (TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_CRITICAL_PERMISSION_GRANT, permissionSetEventStore.UserId)) {
            return false;
        }
        if (!ASSIGNED_TO_USERS.equalsIgnoreCase(permissionSetEventStore.Operation)) {
            return false;
        }
        return !onlyIgnoredPermissions(permissionSetEventStore.PermissionList);
    }

    /**
     * Returns true only when the permission list can be read and every permission is ignored.
     * A blank or unreadable list returns false so the event still triggers.
     */
    private Boolean onlyIgnoredPermissions(String permissionList) {
        if (ignoredPermissions.isEmpty() || String.isBlank(permissionList)) {
            return false;
        }

        Set<String> ignored = new Set<String>();
        for (String name : ignoredPermissions) {
            ignored.add(name.toLowerCase());
        }

        List<Object> permissions;
        try {
            permissions = (List<Object>) JSON.deserializeUntyped(permissionList);
        } catch (Exception ex) {
            return false;
        }
        if (permissions.isEmpty()) {
            return false;
        }

        for (Object permission : permissions) {
            if (!(permission instanceof String) || !ignored.contains(((String) permission).toLowerCase())) {
                return false;
            }
        }
        return true;
    }
}
