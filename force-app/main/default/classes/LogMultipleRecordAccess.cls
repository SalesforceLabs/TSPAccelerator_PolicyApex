/**
 * @description Invocable Apex class to log aggregate record access counts from ListViewEvent, ReportEvent and ApiEvent
 * Security: Uses 'with sharing' to enforce sharing rules and Database.insert in SYSTEM_MODE
 * Note: Only stores aggregate counts (Count_of_Records__c), not individual record IDs
 */
public with sharing class LogMultipleRecordAccess {

    @InvocableMethod(label='Log Aggregate Record Access Counts from Events')
    public static void logAccess(List<InputWrapper> inputs) {
        System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: entered with ' + (inputs != null ? inputs.size() : 0) + ' inputs');
        
        if (inputs == null || inputs.isEmpty()) {
            System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess.logAccess: inputs empty, returning');
            return;
        }

        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        
        for (InputWrapper input : inputs) {
            String recordsJson = input.RecordsField;
            
            System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: processing input, recordsJson=' + (recordsJson != null ? 'present (length=' + recordsJson.length() + ')' : 'null'));
            
            if (String.isBlank(recordsJson)) {
                System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess.logAccess: recordsJson blank, skipping');
                continue;
            }
            
            try {
                Map<String, Object> parsed = (Map<String, Object>) JSON.deserializeUntyped(recordsJson);
                System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: JSON parsed successfully. keys=' + parsed.keySet());
                
                Integer recordCount = null;
                
                // Format 1: {"totalSize":1369,"done":true,"records":[...]} - ApiEvent with totalSize
                if (parsed.containsKey('totalSize')) {
                    System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: found totalSize format');
                    Object totalSizeObj = parsed.get('totalSize');
                    if (totalSizeObj instanceof Integer) {
                        recordCount = (Integer) totalSizeObj;
                    } else if (totalSizeObj instanceof Long) {
                        recordCount = ((Long) totalSizeObj).intValue();
                    } else if (totalSizeObj instanceof Decimal) {
                        recordCount = ((Decimal) totalSizeObj).intValue();
                    }
                    System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: extracted totalSize=' + recordCount);
                }
                // Format 2: {"records": [{"Id": "..."}, ...]} - ListViewEvent/ReportEvent
                // Count the records array instead of storing individual IDs
                else if (parsed.containsKey('records')) {
                    System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: found records array format');
                    List<Object> records = (List<Object>) parsed.get('records');
                    recordCount = records != null ? records.size() : 0;
                    System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: counted ' + recordCount + ' records');
                }
                // Format 3: {"totalSize":1,"rows":[{"datacells":["005...", "001..."]}]}
                // Count unique record IDs from datacells
                else if (parsed.containsKey('rows')) {
                    System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: found rows/datacells format');
                    List<Object> rows = (List<Object>) parsed.get('rows');
                    Set<String> uniqueRecordIds = new Set<String>();
                    
                    if (rows != null) {
                        for (Object rowObj : rows) {
                            Map<String, Object> rowMap = (Map<String, Object>) rowObj;
                            List<Object> datacells = (List<Object>) rowMap.get('datacells');
                            
                            if (datacells != null) {
                                for (Object cellObj : datacells) {
                                    String recordId = (String) cellObj;
                                    if (recordId != null && recordId.length() >= 15) {
                                        uniqueRecordIds.add(recordId);
                                    }
                                }
                            }
                        }
                    }
                    recordCount = uniqueRecordIds.size();
                    System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: counted ' + recordCount + ' unique record IDs');
                }

                // Create a single aggregate log with the count
                if (recordCount != null && recordCount > 0) {
                    System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: creating aggregate log with count=' + recordCount);
                    logs.add(new RecordAccessLog__c(
                        User__c = input.UserId,
                        Count_of_Records__c = recordCount,
                        AccessTime__c = input.EventDate,
                        Queried_Entities__c = input.QueriedEntities,
                        Event_Type__c = input.EventType
                    ));
                } else {
                    System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess.logAccess: no recordCount found or count is 0');
                }
            } catch (JSONException je) {
                // Log parsing failures without exposing sensitive details
                System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess: failed to parse RecordsField JSON.');
            } catch (Exception e) {
                // Intentionally not logging exception details to avoid sensitive info exposure
                System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess: unexpected error while processing RecordsField.');
            }
        }
        
        System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: prepared ' + logs.size() + ' logs for insert');
        
        if (!logs.isEmpty()) {
            System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: attempting Database.insert');
            // Use partial success inserts and SYSTEM_MODE to avoid blocking on single bad rows
            List<Database.SaveResult> results = Database.insert(logs, false, AccessLevel.SYSTEM_MODE);
            System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: Database.insert completed');

            // Avoid throwing from logging; surface only non-sensitive diagnostics
            Integer successCount = 0;
            Integer failCount = 0;
            for (Database.SaveResult sr : results) {
                if (sr == null || sr.isSuccess()) {
                    successCount++;
                    continue;
                }
                failCount++;
                System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess: failed to insert RecordAccessLog__c.');
            }
            System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccess: insert complete. success=' + successCount + ' failed=' + failCount);
        } else {
            System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess.logAccess: logs list is empty, nothing to insert');
        }
    }

    /**
     * @description Publishes record access events for async processing.
     * TSP policies cannot perform DML (limit is 0), so we use Platform Events.
     */
    public static void logAccessAsync(String recordsJson, Id userId, Datetime eventDate, String queriedEntities, String eventType) {
        System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccessAsync: entered. recordsJson=' + (recordsJson != null ? 'present' : 'null') + ' userId=' + userId + ' eventType=' + eventType);
        
        if (String.isBlank(recordsJson) || userId == null || eventDate == null) {
            System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess.logAccessAsync: invalid parameters, returning early');
            return;
        }
        
        // TSP policies run synchronously with DML limit of 0.
        // Publish a Platform Event that will be consumed by a Flow to create RecordAccessLog__c records.
        try {
            System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccessAsync: publishing RecordAccessEvent__e');
            
            RecordAccessEvent__e evt = new RecordAccessEvent__e(
                UserId__c = userId,
                RecordsJson__c = recordsJson,
                AccessTime__c = eventDate,
                QueriedEntities__c = queriedEntities,
                EventType__c = eventType
            );
            
            List<Database.SaveResult> results = EventBus.publish(new List<RecordAccessEvent__e>{ evt });
            
            if (results != null && !results.isEmpty() && results[0].isSuccess()) {
                System.debug(LoggingLevel.INFO, 'LogMultipleRecordAccess.logAccessAsync: Platform Event published successfully');
            } else {
                System.debug(LoggingLevel.ERROR, 'LogMultipleRecordAccess.logAccessAsync: Platform Event publish failed');
            }
        } catch (Exception ex) {
            System.debug(LoggingLevel.ERROR, 'LogMultipleRecordAccess.logAccessAsync: failed to publish Platform Event. type=' + ex.getTypeName() + ' message=' + ex.getMessage());
        }
    }

    private class LogAccessQueueable implements Queueable {
        private final String recordsJson;
        private final Id userId;
        private final Datetime eventDate;

        private LogAccessQueueable(String recordsJson, Id userId, Datetime eventDate) {
            this.recordsJson = recordsJson;
            this.userId = userId;
            this.eventDate = eventDate;
        }

        public void execute(QueueableContext context) {
            try {
                InputWrapper input = new InputWrapper();
                input.RecordsField = recordsJson;
                input.UserId = userId;
                input.EventDate = eventDate;
                LogMultipleRecordAccess.logAccess(new List<InputWrapper>{ input });
            } catch (Exception e) {
                // Don't fail the async job in a security policy pipeline; keep errors non-blocking.
                System.debug(LoggingLevel.WARN, 'LogMultipleRecordAccess: async logging job failed.');
            }
        }
    }
    
    public class InputWrapper {
        @InvocableVariable(required=true)
        public String RecordsField; 
        
        @InvocableVariable(required=true)
        public Id UserId; 
        
        @InvocableVariable(required=true)
        public Datetime EventDate;
        
        @InvocableVariable(required=false)
        public String QueriedEntities;
        
        @InvocableVariable(required=false)
        public String EventType;
    }
}