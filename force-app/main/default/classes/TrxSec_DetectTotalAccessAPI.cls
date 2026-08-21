
/**
 * @description Transaction Security Policy condition to detect high-volume record access via API queries
 */
global with sharing class TrxSec_DetectTotalAccessAPI implements TxnSecurity.EventCondition {

    global Boolean evaluate(SObject event) {
        // Cast the event to ApiEvent
        ApiEvent e = (ApiEvent) event;

        // Subscriber-configured exclusions are honored before anything else, including logging, so an
        // excluded user produces no RecordAccessLog__c history and can never trip this policy.
        if (TrxSec_PolicyExclusions.isExcluded(TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API, e.UserId)) {
            return false;
        }
        
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
        
        // Derive this event's own record count so the operation being evaluated contributes to the
        // decision that gates it. logAccessAsync above only publishes a Platform Event, so the row
        // for this event is not persisted until a subscribing Flow runs; without this the aggregate
        // below sees history only and a single unbounded query in a fresh window can never trip the
        // threshold. The same extractRecordCount call is what the Flow's logAccess uses to derive
        // Count_of_Records__c, so this in-memory count and the persisted history share one basis.
        //
        // ApiEvent.RowsProcessed is deliberately not used: it is -1 for big object queries whose
        // row count exceeds the API batch size, which would silently reduce the total.
        Integer currentEventRecordCount = 0;
        try {
            currentEventRecordCount = LogMultipleRecordAccess.extractRecordCount(e.Records);
        } catch (Exception ex) {
            // Fall through to the historical-only comparison rather than letting anything escape a
            // TSP condition, where a thrown exception has unpredictable enforcement consequences.
            System.debug(LoggingLevel.WARN, 'TrxSec_DetectTotalAccessAPI: could not derive current event record count, treating as 0. type=' + ex.getTypeName());
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

        Integer threshold = TrxSec_ThresholdSettings.getThreshold(TrxSec_ThresholdSettings.EVENT_API);
        return combinedRecordsAccessed > threshold;
    }

}