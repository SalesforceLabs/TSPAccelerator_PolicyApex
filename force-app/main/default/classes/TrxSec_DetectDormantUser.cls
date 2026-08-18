/**
 * @description Transaction Security Policy condition to detect login attempts by dormant user accounts
 */
global with sharing class TrxSec_DetectDormantUser implements TxnSecurity.EventCondition {
    
    // Configurable threshold: Number of days without a successful login to consider account dormant
    private static final Integer DORMANT_DAYS_THRESHOLD = 90;

    public class LoginAttempt {
        public DateTime loginTime;
        public String status;

        public LoginAttempt(DateTime loginTime, String status) {
            this.loginTime = loginTime;
            this.status = status;
        }
    }

    public interface Provider {
        List<LoginAttempt> getLoginsInWindow(Id userId, DateTime windowStart, DateTime currentLoginTime);
        Boolean hasAnyLoginHistory(Id userId, DateTime currentLoginTime);
    }

    @TestVisible
    private static Provider provider = new DefaultProvider();

    @TestVisible
    private static void resetProviderForTest() {
        provider = new DefaultProvider();
    }
    
    global Boolean evaluate(SObject event) {
        switch on event {
            when LoginEvent loginEvent {
                return evaluate(loginEvent);
            }
            when else {
                return false;
            }
        }
    }
    
    private Boolean evaluate(LoginEvent loginEvent) {
        try {
            // Check for required fields
            if (loginEvent.UserId == null || loginEvent.EventDate == null) {
                return false;
            }
            
            // Get the current login timestamp
            DateTime currentLoginTime = loginEvent.EventDate;
            DateTime windowStart = currentLoginTime.addDays(-DORMANT_DAYS_THRESHOLD);
            
            // Fetch logins via provider so tests can be deterministic across orgs.
            // Note: Status cannot be filtered in SOQL on LoginHistory, so the query is bounded by
            // the dormancy window and the success check is done in memory.
            List<LoginAttempt> loginsInWindow = provider.getLoginsInWindow(loginEvent.UserId, windowStart, currentLoginTime);
            for (LoginAttempt login : loginsInWindow) {
                if (login != null && login.status == 'Success') {
                    return false;
                }
            }
            
            // No successful login inside the window. A user with no login history at all is a new
            // account rather than a dormant one, so the policy does not apply.
            return provider.hasAnyLoginHistory(loginEvent.UserId, currentLoginTime);
            
        } catch (Exception e) {
            // Return false to prevent blocking legitimate logins
            // Security: Not logging exception details to prevent sensitive info exposure
            return false;
        }
    }

    private with sharing class DefaultProvider implements Provider {
        public List<LoginAttempt> getLoginsInWindow(Id userId, DateTime windowStart, DateTime currentLoginTime) {
            List<LoginHistory> histories = [
                SELECT LoginTime, UserId, Status
                FROM LoginHistory
                WHERE UserId = :userId
                    AND LoginTime < :currentLoginTime
                    AND LoginTime >= :windowStart
                ORDER BY LoginTime DESC
            ];

            List<LoginAttempt> attempts = new List<LoginAttempt>();
            for (LoginHistory history : histories) {
                attempts.add(new LoginAttempt(history.LoginTime, history.Status));
            }
            return attempts;
        }

        public Boolean hasAnyLoginHistory(Id userId, DateTime currentLoginTime) {
            return ![
                SELECT Id
                FROM LoginHistory
                WHERE UserId = :userId
                    AND LoginTime < :currentLoginTime
                LIMIT 1
            ].isEmpty();
        }
    }
}
