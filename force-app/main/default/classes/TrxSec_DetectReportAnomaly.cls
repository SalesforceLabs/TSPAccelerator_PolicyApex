/**
 * @description Transaction Security Policy condition to detect anomalous report access patterns
 */
global with sharing class TrxSec_DetectReportAnomaly implements TxnSecurity.EventCondition {
    
    global Boolean evaluate(SObject event) {
        switch on event{
            when ReportAnomalyEventStore reportAnomalyEventStore {
                return evaluate(reportAnomalyEventStore);
            }
            when null {
                // Don't take policy action when event is null
                return false;
            }
            when else{
                // Don't take policy action when event is not handled
                return false;
            }
        }
    }
    private boolean evaluate(ReportAnomalyEventStore reportAnomalyEventStore) {
        return true;
    }
}