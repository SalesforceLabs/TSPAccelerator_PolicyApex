/**
 * @description Transaction Security Policy condition to detect Login As events
 */
global with sharing class TrxSec_DetectLoginAsEvent implements TxnSecurity.EventCondition {
    /***********************************************************
    * DETECT LOGIN AS EVENTS.
    * LoginAsEvent is triggered when an administrator logs in as another user.
    * This policy detects all Login As events for monitoring and security purposes.
    ***********************************************************/

    global boolean evaluate(SObject event){
        LoginAsEvent e = (LoginAsEvent) event;

        // LoginAsEvent.UserId is the impersonated user. Exclusions apply to the
        // administrator performing Login As, whose username is DelegatedUsername.
        if (TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_LOGIN_AS,
            userIdFromUsername(e.DelegatedUsername)
        )) {
            return false;
        }

        // Simply return true to trigger on all LoginAsEvent occurrences
        return true;
    }

    /**
     * Resolves a username to a User Id. One bound SOQL row so the lookup stays
     * within TxnSecurity.EventCondition query limits. Returns null when the
     * username is blank, no User matches, or the query throws: isExcluded treats
     * null as not excluded, which keeps the policy enforcing.
     */
    private static Id userIdFromUsername(String username) {
        if (String.isBlank(username)) {
            return null;
        }
        try {
            List<User> users = [
                SELECT Id
                FROM User
                WHERE Username = :username.trim()
                LIMIT 1
            ];
            return users.isEmpty() ? null : users[0].Id;
        } catch (Exception ex) {
            System.debug(
                LoggingLevel.WARN,
                'TrxSec_DetectLoginAsEvent.userIdFromUsername: treating as unresolved due to ' +
                    ex.getTypeName()
            );
            return null;
        }
    }
}
