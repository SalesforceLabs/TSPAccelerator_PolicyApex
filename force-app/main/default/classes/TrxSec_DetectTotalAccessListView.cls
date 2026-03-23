/**
 * @description Transaction Security Policy condition to detect high-volume record access via list views
 */
global with sharing class TrxSec_DetectTotalAccessListView implements TxnSecurity.EventCondition {
    
    // Threshold for unique record access within last 24 hours
    private static final Integer THRESHOLD = 10000;
    
    global Boolean evaluate(SObject event) {
        // Cast the event to ListViewEvent
        ListViewEvent e = (ListViewEvent) event;
        
        if (e.UserId == null || e.EventDate == null) {
            return false;
        }
        
        // Persist accessed record IDs for future evaluations (replacing Flow-based logging).
        // ListViewEvent.Records contains JSON with the list of record IDs accessed.
        // Now stored as aggregate count instead of individual IDs.
        try {
            String recordsJson = e.Records;
            if (!String.isBlank(recordsJson)) {
                LogMultipleRecordAccess.logAccessAsync(recordsJson, e.UserId, e.EventDate, e.QueriedEntities, 'ListViewEvent');
            }
        } catch (Exception ex) {
            // Never block TSP evaluation on logging failures
            System.debug(LoggingLevel.WARN, 'TrxSec_DetectTotalAccessListView: failed to start access logging. type=' + ex.getTypeName());
        }
        
        // Define the 24-hour window
        Datetime windowStart = e.EventDate.addHours(-24);
        
        // Query custom object for aggregate record counts accessed by this user in the last 24 hours
        // All event types now store aggregate counts only
        Integer totalRecordsAccessed = 0;
        
        for (RecordAccessLog__c log : [
            SELECT Count_of_Records__c
            FROM RecordAccessLog__c
            WHERE User__c = :e.UserId 
                AND AccessTime__c >= :windowStart
                AND Count_of_Records__c != null
        ]) {
            totalRecordsAccessed += Integer.valueOf(log.Count_of_Records__c);
        }
        
        return totalRecordsAccessed > THRESHOLD;
    }
}