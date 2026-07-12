/**
 * @description Invocable + Batch Apex class to delete old RecordAccessLog__c records.
 *
 * The invocable method (called from Flow) no longer deletes records inline. Instead it
 * enqueues this class as a Batch Apex job. Each batch chunk runs in its own transaction
 * with its own governor limits, so the previous "Too many query rows: 50001" and
 * "Too many DML rows: 10001" failures on large data volumes (~200k rows) no longer occur.
 *
 * Within each chunk the records are deleted with allOrNone = false (so a few bad rows do
 * not roll back the whole chunk) and then hard-deleted by purging ONLY those rows from the
 * Recycle Bin (the rest of the org's Recycle Bin is left untouched).
 *
 * The invocable method and its request/result wrapper classes are global so that subscribers
 * of the managed package can invoke this action from their own flows, the Actions REST API,
 * or Apex. Only the entry-point API surface is global; internal helpers remain private.
 */
global with sharing class DeleteOldRecordAccessLogs implements Database.Batchable<SObject>, Database.Stateful {

    // Batch scope size. Comfortably under the 10,000 DML rows limit per transaction.
    @TestVisible
    private static final Integer BATCH_SCOPE_SIZE = 2000;

    // Database.emptyRecycleBin is capped at 200 records per call.
    private static final Integer RECYCLE_BIN_CHUNK_SIZE = 200;

    private final Integer daysThreshold;

    // Stateful counters, surfaced in finish() for monitoring/troubleshooting.
    private Integer totalSoftDeleted = 0;
    private Integer totalHardDeleted = 0;

    // Transaction-scoped counters for test verification. ALL ROWS does not reliably reflect a
    // same-transaction Recycle Bin purge, so tests assert against these instead.
    @TestVisible
    private static Integer softDeletedThisTransaction = 0;
    @TestVisible
    private static Integer hardDeletedThisTransaction = 0;

    global DeleteOldRecordAccessLogs(Integer daysThreshold) {
        this.daysThreshold = daysThreshold;
    }

    /**
     * @description Invocable entry point for Flow. Validates input and enqueues a Batch Apex
     *              job to perform the deletion asynchronously.
     * @param requests List of cleanup requests with threshold configuration
     * @return List of cleanup results indicating whether the job was enqueued
     */
    @InvocableMethod(
        label='Delete Old Record Access Logs'
        description='Enqueues a batch job to delete RecordAccessLog__c records older than a specified number of days.'
        category='Transaction Security'
    )
    global static List<CleanupResult> deleteOldRecords(List<CleanupRequest> requests) {
        List<CleanupResult> results = new List<CleanupResult>();

        for (CleanupRequest request : requests) {
            CleanupResult result = new CleanupResult();

            // Validate input
            if (request.daysThreshold == null || request.daysThreshold < 0) {
                result.success = false;
                result.errorMessage = 'Invalid threshold: Days threshold must be a non-negative integer.';
                results.add(result);
                continue;
            }

            try {
                Id jobId = Database.executeBatch(
                    new DeleteOldRecordAccessLogs(request.daysThreshold),
                    BATCH_SCOPE_SIZE
                );
                result.success = true;
                result.jobId = jobId;
                result.errorMessage = null;
            } catch (Exception e) {
                result.success = false;
                // Security: generic message without exposing internal exception details.
                result.errorMessage = 'Unable to start the record cleanup job. Please try again.';
            }

            results.add(result);
        }

        return results;
    }

    global Database.QueryLocator start(Database.BatchableContext bc) {
        // QueryLocator streams rows and is not subject to the 50,000 query-rows limit.
        Date cutoffDate = Date.today().addDays(-daysThreshold);
        return Database.getQueryLocator([
            SELECT Id
            FROM RecordAccessLog__c
            WHERE CreatedDate < :cutoffDate
        ]);
    }

    global void execute(Database.BatchableContext bc, List<RecordAccessLog__c> scope) {
        if (scope == null || scope.isEmpty()) {
            return;
        }

        // allOrNone = false: individual row failures don't roll back the whole chunk.
        List<Database.DeleteResult> deleteResults = Database.delete(scope, false, AccessLevel.SYSTEM_MODE);

        // Build the purge list from only the rows that were deleted successfully.
        List<Id> deletedIds = new List<Id>();
        for (Database.DeleteResult dr : deleteResults) {
            if (dr.isSuccess()) {
                deletedIds.add(dr.getId());
            }
        }
        this.totalSoftDeleted += deletedIds.size();
        softDeletedThisTransaction += deletedIds.size();

        // Hard delete: purge ONLY the rows we just deleted from the Recycle Bin.
        hardDelete(deletedIds);
    }

    global void finish(Database.BatchableContext bc) {
        System.debug(LoggingLevel.INFO,
            'DeleteOldRecordAccessLogs finished. Soft-deleted=' + this.totalSoftDeleted
            + ', hard-deleted=' + this.totalHardDeleted);
    }

    /**
     * @description Permanently removes the given record Ids from the Recycle Bin in chunks of
     *              up to 200 (the emptyRecycleBin per-call cap). Best-effort: a purge failure is
     *              logged but does not roll back the already-successful soft delete.
     */
    private void hardDelete(List<Id> deletedIds) {
        for (Integer i = 0; i < deletedIds.size(); i += RECYCLE_BIN_CHUNK_SIZE) {
            Integer endIndex = Math.min(i + RECYCLE_BIN_CHUNK_SIZE, deletedIds.size());
            List<Id> chunk = new List<Id>();
            for (Integer j = i; j < endIndex; j++) {
                chunk.add(deletedIds[j]);
            }

            try {
                Database.emptyRecycleBin(chunk);
                this.totalHardDeleted += chunk.size();
                hardDeletedThisTransaction += chunk.size();
            } catch (Exception e) {
                System.debug(LoggingLevel.WARN,
                    'emptyRecycleBin failed for a chunk; rows remain soft-deleted. ' + e.getMessage());
            }
        }
    }

    /**
     * @description Input wrapper class for Flow integration
     */
    global class CleanupRequest {
        @InvocableVariable(
            label='Days Threshold'
            description='Number of days to use as threshold. Records older than this will be deleted.'
            required=true
        )
        global Integer daysThreshold;
    }

    /**
     * @description Output wrapper class for Flow integration.
     *              Note: deletion is asynchronous; success indicates whether the batch job was
     *              successfully enqueued, not how many records were ultimately deleted.
     */
    global class CleanupResult {
        @InvocableVariable(
            label='Success'
            description='Whether the batch cleanup job was successfully enqueued'
        )
        global Boolean success;

        @InvocableVariable(
            label='Job Id'
            description='The Id of the enqueued Batch Apex job (AsyncApexJob), if any'
        )
        global Id jobId;

        @InvocableVariable(
            label='Error Message'
            description='Error message if the job could not be enqueued'
        )
        global String errorMessage;
    }
}
