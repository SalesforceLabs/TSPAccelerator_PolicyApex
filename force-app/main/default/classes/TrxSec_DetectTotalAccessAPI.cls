
/**
 * @description Transaction Security Policy condition to detect high-volume record access via API queries
 */
global with sharing class TrxSec_DetectTotalAccessAPI implements TxnSecurity.EventCondition {
    
    // Threshold for unique record access within last 24 hours
    private static final Integer THRESHOLD = 10000;
    
    global Boolean evaluate(SObject event) {
        // Cast the event to ApiEvent
        ApiEvent e = (ApiEvent) event;
        
        if (e.UserId == null || e.EventDate == null) {
            return false;
        }

        // Persist accessed record count for future evaluations.
        // ApiEvent.Records contains JSON with totalSize: {"totalSize":1369,"done":true,"records":[...]}
        // We extract totalSize and log it as an aggregate count for efficient storage.
        try {
            String recordsJson = e.Records;
            System.debug(LoggingLevel.INFO, 'TrxSec_DetectTotalAccessAPI: e.Records=' + (recordsJson != null ? 'present (length=' + recordsJson.length() + ')' : 'null'));
            
            if (!String.isBlank(recordsJson)) {
                System.debug(LoggingLevel.INFO, 'TrxSec_DetectTotalAccessAPI: calling logAccessAsync');
                LogMultipleRecordAccess.logAccessAsync(recordsJson, e.UserId, e.EventDate, e.QueriedEntities, 'ApiEvent');
                System.debug(LoggingLevel.INFO, 'TrxSec_DetectTotalAccessAPI: logAccessAsync returned');
            } else {
                System.debug(LoggingLevel.WARN, 'TrxSec_DetectTotalAccessAPI: e.Records is blank, skipping logging');
            }
        } catch (Exception ex) {
            // Never block TSP evaluation on logging failures
            System.debug(LoggingLevel.ERROR, 'TrxSec_DetectTotalAccessAPI: failed to start access logging. type=' + ex.getTypeName() + ' message=' + ex.getMessage());
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