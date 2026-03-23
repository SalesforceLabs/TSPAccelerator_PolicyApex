/**
 * @description Transaction Security Policy condition to detect impossible travel based on location and time differences between logins
 */
global with sharing class TrxSec_DetectImpossibleTravel implements TxnSecurity.EventCondition {

    public class LoginSnapshot {
        public DateTime loginTime;
        public String countryIso;
        public String city;

        public LoginSnapshot(DateTime loginTime, String countryIso, String city) {
            this.loginTime = loginTime;
            this.countryIso = countryIso;
            this.city = city;
        }
    }

    public interface Provider {
        LoginSnapshot getMostRecentLogin(Id userId);
    }

    @TestVisible
    private static Provider provider = new DefaultProvider();

    @TestVisible
    private static void resetProviderForTest() {
        provider = new DefaultProvider();
    }
    
    global Boolean evaluate(SObject event) {
        LoginEvent e;
        try {
            e = (LoginEvent) event;
        } catch (Exception ex) {
            return false;
        }
        
        try {
            if (e == null || e.UserId == null || e.EventDate == null) {
                return false;
            }
            
            // Fetch the most recent login for this user
            LoginSnapshot last = provider.getMostRecentLogin(e.UserId);
            if (last != null && last.loginTime != null) {
                
                // Calculate time difference in minutes
                Long minutesDiff = Math.abs((e.EventDate.getTime() - last.loginTime.getTime()) / (1000 * 60));
                
                // Trigger only if login is within 30 mins and city or country has changed
                if (minutesDiff < 30) {
                    Boolean cityChanged = (last.city != e.City);
                    Boolean countryChanged = (last.countryIso != e.CountryIso);
                    
                    if (cityChanged || countryChanged) {
                        return true;
                    }
                }
            }
            
            return false;
        } catch (Exception ex) {
            // Fail-safe: never block due to unexpected errors
            return false;
        }
    }

    private with sharing class DefaultProvider implements Provider {
        public LoginSnapshot getMostRecentLogin(Id userId) {
            List<LoginHistory> pastLogins = [
                SELECT LoginTime, CountryIso, LoginGeo.City
                FROM LoginHistory
                WHERE UserId = :userId
                ORDER BY LoginTime DESC
                LIMIT 1
            ];

            if (pastLogins.isEmpty()) {
                return null;
            }

            LoginHistory last = pastLogins[0];
            String lastCity = (last.LoginGeo != null) ? last.LoginGeo.City : null;
            return new LoginSnapshot(last.LoginTime, last.CountryIso, lastCity);
        }
    }
}