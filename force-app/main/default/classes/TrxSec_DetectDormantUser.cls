/**
 * @description Transaction Security Policy condition to detect login attempts by dormant user accounts
 */
global with sharing class TrxSec_DetectDormantUser implements TxnSecurity.EventCondition {
    
    // Configurable threshold: Number of days without login to consider account dormant
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
        List<LoginAttempt> getRecentLogins(Id userId, DateTime currentLoginTime);
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
            
            // Fetch recent logins via provider so tests can be deterministic across orgs
            // Note: Status field cannot be filtered directly in SOQL, so we query more records
            // and filter in memory to find the last successful login
            List<LoginAttempt> recentLogins = provider.getRecentLogins(loginEvent.UserId, currentLoginTime);
            
            // Filter to find the most recent successful login
            DateTime lastLoginTime = null;
            for (LoginAttempt login : recentLogins) {
                if (login != null && login.status == 'Success') {
                    lastLoginTime = login.loginTime;
                    break; // Found the most recent successful login
                }
            }
            
            // If no previous successful login found, this could be the first successful login
            // or all recent logins were failures
            if (lastLoginTime == null) {
                // Optional: Return true for first-time logins requiring extra verification
                // Or return false to skip first-time logins
                return false; // Change to true if you want to flag first-time logins
            }
            
            // Calculate days since last login
            Long millisecondsSinceLastLogin = currentLoginTime.getTime() - lastLoginTime.getTime();
            Integer daysSinceLastLogin = (Integer)(millisecondsSinceLastLogin / (1000 * 60 * 60 * 24));
            
            // Return true if the account has been dormant beyond the threshold
            return daysSinceLastLogin >= DORMANT_DAYS_THRESHOLD;
            
        } catch (Exception e) {
            // Return false to prevent blocking legitimate logins
            // Security: Not logging exception details to prevent sensitive info exposure
            return false;
        }
    }

    private with sharing class DefaultProvider implements Provider {
        public List<LoginAttempt> getRecentLogins(Id userId, DateTime currentLoginTime) {
            List<LoginHistory> histories = [
                SELECT LoginTime, UserId, Status
                FROM LoginHistory
                WHERE UserId = :userId
                    AND LoginTime < :currentLoginTime
                ORDER BY LoginTime DESC
                LIMIT 10
            ];

            List<LoginAttempt> attempts = new List<LoginAttempt>();
            for (LoginHistory history : histories) {
                attempts.add(new LoginAttempt(history.LoginTime, history.Status));
            }
            return attempts;
        }
    }
}

