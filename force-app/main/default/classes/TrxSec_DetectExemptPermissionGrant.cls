/**
 * @description Transaction Security Policy condition to detect the enabling or assignment of the
 * TransactionSecurityExempt permission, which would let a user bypass every Transaction Security
 * Policy. Intended as a blocking policy on PermissionSetEventStore. A user with a
 * Policy_Exclusion__mdt record for this policy (for example the CI/CD user) is never blocked.
 */
global with sharing class TrxSec_DetectExemptPermissionGrant implements TxnSecurity.EventCondition {

    private static final String EXEMPT_PERMISSION = 'TransactionSecurityExempt';
    private static final Set<String> GRANTING_OPERATIONS = new Set<String>{ 'permsenabled', 'assignedtousers' };

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
            TrxSec_PolicyExclusions.POLICY_EXEMPT_PERMISSION_GRANT, permissionSetEventStore.UserId)) {
            return false;
        }
        if (String.isBlank(permissionSetEventStore.Operation)
            || String.isBlank(permissionSetEventStore.PermissionList)) {
            return false;
        }

        return GRANTING_OPERATIONS.contains(permissionSetEventStore.Operation.toLowerCase())
            && permissionSetEventStore.PermissionList.containsIgnoreCase(EXEMPT_PERMISSION);
    }
}
