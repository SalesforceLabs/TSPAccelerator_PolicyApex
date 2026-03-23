/**
 * @description Invocable Apex class to delete old RecordAccessLog__c records
 * This class can be called from Flow to clean up historical record access logs
 * based on a configurable day threshold
 * 
 */
public with sharing class DeleteOldRecordAccessLogs {
    
    /**
     * @description Invocable method to delete RecordAccessLog__c records older than specified days
     * @param requests List of cleanup requests with threshold configuration
     * @return List of cleanup results with success status and record count
     */
    @InvocableMethod(
        label='Delete Old Record Access Logs'
        description='Deletes RecordAccessLog__c records older than a specified number of days.'
        category='Transaction Security'
    )
    public static List<CleanupResult> deleteOldRecords(List<CleanupRequest> requests) {
        List<CleanupResult> results = new List<CleanupResult>();
        
        for (CleanupRequest request : requests) {
            CleanupResult result = new CleanupResult();
            
            // Validate input
            if (request.daysThreshold == null || request.daysThreshold < 0) {
                result.success = false;
                result.recordsDeleted = 0;
                result.errorMessage = 'Invalid threshold: Days threshold must be a non-negative integer.';
                results.add(result);
                continue;
            }
            
            try {
                // Calculate the cutoff date
                Date cutoffDate = Date.today().addDays(-request.daysThreshold);
                
                // Query records older than the threshold
                List<RecordAccessLog__c> recordsToDelete = [
                    SELECT Id
                    FROM RecordAccessLog__c
                    WHERE CreatedDate < :cutoffDate
                ];
                
                // Delete the records in System Mode
                if (!recordsToDelete.isEmpty()) {
                    Database.delete(recordsToDelete, AccessLevel.SYSTEM_MODE);
                    result.success = true;
                    result.recordsDeleted = recordsToDelete.size();
                    result.errorMessage = null;
                } else {
                    result.success = true;
                    result.recordsDeleted = 0;
                    result.errorMessage = null;
                }
                
            } catch (Exception e) {
                result.success = false;
                result.recordsDeleted = 0;
                // Security: Generic error message without exposing sensitive exception details
                result.errorMessage = 'Error deleting records. Please check permissions and try again.';
            }
            
            results.add(result);
        }
        
        return results;
    }
    
    /**
     * @description Input wrapper class for Flow integration
     */
    public class CleanupRequest {
        @InvocableVariable(
            label='Days Threshold'
            description='Number of days to use as threshold. Records older than this will be deleted.'
            required=true
        )
        public Integer daysThreshold;
    }
    
    /**
     * @description Output wrapper class for Flow integration
     */
    public class CleanupResult {
        @InvocableVariable(
            label='Records Deleted'
            description='Number of records successfully deleted'
        )
        public Integer recordsDeleted;
        
        @InvocableVariable(
            label='Success'
            description='Whether the operation completed successfully'
        )
        public Boolean success;
        
        @InvocableVariable(
            label='Error Message'
            description='Error message if the operation failed'
        )
        public String errorMessage;
    }
}

