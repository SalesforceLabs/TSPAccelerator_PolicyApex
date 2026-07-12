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
        
        // Aggregate the record counts accessed by this user in the last 24 hours.
        // SUM is performed in the database so the metered TSP evaluation does not iterate
        // (potentially hundreds of thousands of) rows in Apex. CreatedDate is used because it
        // is automatically indexed (AccessTime__c is not and cannot be indexed in a managed
        // package); combined with the indexed User__c lookup this keeps the query selective.
        // All event types (ApiEvent, ListViewEvent, ReportEvent) store aggregate counts only.
        AggregateResult ar = [
            SELECT SUM(Count_of_Records__c) totalRecords
            FROM RecordAccessLog__c
            WHERE User__c = :e.UserId 
                AND CreatedDate >= :windowStart
        ];
        
        Decimal totalRecordsAccessed = (Decimal) ar.get('totalRecords');
        
        return totalRecordsAccessed != null && totalRecordsAccessed > THRESHOLD;
    }
}