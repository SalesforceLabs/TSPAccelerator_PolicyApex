/**
 * @description Transaction Security Policy condition to detect high-volume record access via report exports
 */
global with sharing class TrxSec_DetectTotalAccessReportExport implements TxnSecurity.EventCondition {
    
    // Threshold for unique record access within last 24 hours
    private static final Integer THRESHOLD = 10000;
    
    global Boolean evaluate(SObject event) {
        // Cast the event to reportEvent
        reportEvent e = (reportEvent) event;
        
         // Only evaluate if this is a report export operation. All three export values in the
         // Operation picklist must reach the logging and counting below; matching only the exact
         // string 'ReportExported' skipped asynchronous exports, which is the path Salesforce uses
         // for large exports, so those records never reached RecordAccessLog__c at all and the
         // 24-hour aggregate every total-access policy reads was under-counted.
        if (!TrxSec_ReportEventUtils.isReportExportOperation(e.Operation)) {
            return false;
        }
        
        // Persist accessed record IDs for future evaluations (replacing Flow-based logging).
        // ReportEvent.Records contains JSON with the list of record IDs in the exported report.
        // Now stored as aggregate count instead of individual IDs.
        try {
            String recordsJson = e.Records;
            if (!String.isBlank(recordsJson)) {
                LogMultipleRecordAccess.logAccessAsync(recordsJson, e.UserId, e.EventDate, e.QueriedEntities, 'ReportEvent');
            }
        } catch (Exception ex) {
            // Never block TSP evaluation on logging failures
            System.debug(LoggingLevel.WARN, 'TrxSec_DetectTotalAccessReportExport: failed to start access logging. type=' + ex.getTypeName());
        }
        
        // Derive this event's own record count so the export being evaluated contributes to the
        // decision that gates it. logAccessAsync above only publishes a Platform Event, so the row
        // for this event is not persisted until a subscribing Flow runs; without this the aggregate
        // below sees history only and a single unbounded export in a fresh window can never trip the
        // threshold. The same extractRecordCount call is what the Flow's logAccess uses to derive
        // Count_of_Records__c, so this in-memory count and the persisted history share one basis.
        //
        // ReportEvent.RowsProcessed is deliberately not used. When a report execution is chunked,
        // every ReportEvent sharing an ExecutionIdentifier carries the SAME RowsProcessed (the total
        // for the whole execution) and differs only in Records and Sequence, so adding RowsProcessed
        // per event would count an N-chunk export N times. Records holds this chunk's own data,
        // which is also the unit logAccessAsync publishes per chunk, so each chunk is counted
        // exactly once and no cross-event de-duplication by ExecutionIdentifier is needed.
        Integer currentEventRecordCount = 0;
        try {
            currentEventRecordCount = LogMultipleRecordAccess.extractRecordCount(e.Records);
        } catch (Exception ex) {
            // Fall through to the historical-only comparison rather than letting anything escape a
            // TSP condition, where a thrown exception has unpredictable enforcement consequences.
            System.debug(LoggingLevel.WARN, 'TrxSec_DetectTotalAccessReportExport: could not derive current event record count, treating as 0. type=' + ex.getTypeName());
            currentEventRecordCount = 0;
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
        
        // SUM returns null when the user has no rows in the window; treat that as zero history.
        Decimal historicalRecordsAccessed = totalRecordsAccessed != null ? totalRecordsAccessed : 0;
        Decimal combinedRecordsAccessed = historicalRecordsAccessed + currentEventRecordCount;
        
        return combinedRecordsAccessed > THRESHOLD;
    }
}