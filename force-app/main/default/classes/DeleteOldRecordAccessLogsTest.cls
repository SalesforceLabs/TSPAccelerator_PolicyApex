/**
 * @description Test class for DeleteOldRecordAccessLogs.
 *
 * The class now runs deletion asynchronously via Batch Apex, so the invocable method only
 * reports whether the job was enqueued (success + jobId); the actual deletion happens when
 * the batch runs at Test.stopTest(). These tests cover enqueue validation, the batch delete
 * path, and verify that deleted rows are hard-deleted (purged from the Recycle Bin).
 */
@isTest
private class DeleteOldRecordAccessLogsTest {

    private static final Integer SETUP_RECORD_COUNT = 8;

    @testSetup
    static void setupTestData() {
        List<RecordAccessLog__c> testRecords = new List<RecordAccessLog__c>();
        for (Integer i = 0; i < SETUP_RECORD_COUNT; i++) {
            testRecords.add(new RecordAccessLog__c(
                User__c = UserInfo.getUserId(),
                Count_of_Records__c = 100 + (i * 10),
                AccessTime__c = DateTime.now().addDays(-i * 10)
            ));
        }
        insert testRecords;
    }

    private static DeleteOldRecordAccessLogs.CleanupRequest buildRequest(Integer daysThreshold) {
        DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
        request.daysThreshold = daysThreshold;
        return request;
    }

    private static List<DeleteOldRecordAccessLogs.CleanupResult> invoke(DeleteOldRecordAccessLogs.CleanupRequest request) {
        return DeleteOldRecordAccessLogs.deleteOldRecords(
            new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
    }

    private static Integer batchJobCount() {
        return [
            SELECT COUNT()
            FROM AsyncApexJob
            WHERE ApexClass.Name = 'DeleteOldRecordAccessLogs' AND JobType = 'BatchApex'
        ];
    }

    /**
     * @description Records older than the threshold are deleted AND hard-deleted (purged from
     *              the Recycle Bin), while newer records are left intact.
     */
    @isTest
    static void testBatchDeletesAndHardDeletesOldRecords() {
        List<RecordAccessLog__c> allLogs = [SELECT Id FROM RecordAccessLog__c ORDER BY CreatedDate ASC];
        System.assert(allLogs.size() >= 2, 'Expected at least 2 records from setup');

        // Backdate two records so they fall outside the 30-day threshold.
        Test.setCreatedDate(allLogs[0].Id, DateTime.now().addDays(-120));
        Test.setCreatedDate(allLogs[1].Id, DateTime.now().addDays(-45));
        Set<Id> oldIds = new Set<Id>{ allLogs[0].Id, allLogs[1].Id };

        Integer initialCount = [SELECT COUNT() FROM RecordAccessLog__c];

        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(30));
        Test.stopTest(); // batch executes here

        System.assertEquals(1, results.size(), 'Should return one result');
        System.assertEquals(true, results[0].success, 'Batch job should be enqueued');
        System.assertNotEquals(null, results[0].jobId, 'Job Id should be populated');
        System.assertEquals(null, results[0].errorMessage, 'Should have no error message');

        Integer remaining = [SELECT COUNT() FROM RecordAccessLog__c];
        System.assertEquals(initialCount - 2, remaining, 'The two old records should be deleted');

        // The two old records must be gone from normal (non-deleted) results.
        Integer stillLive = [SELECT COUNT() FROM RecordAccessLog__c WHERE Id IN :oldIds];
        System.assertEquals(0, stillLive, 'The two old records should no longer be live');

        // Hard-delete verification: emptyRecycleBin succeeds for exactly the rows we deleted.
        // (ALL ROWS does not reliably reflect a same-transaction Recycle Bin purge, so we assert
        // against the class's transaction-scoped purge counter instead.)
        System.assertEquals(2, DeleteOldRecordAccessLogs.softDeletedThisTransaction,
            'Both old records should have been soft-deleted by the batch');
        System.assertEquals(2, DeleteOldRecordAccessLogs.hardDeletedThisTransaction,
            'Both deleted records should have been hard-deleted (purged from the Recycle Bin)');
    }

    /**
     * @description A valid threshold that matches no records still enqueues a job and deletes nothing.
     */
    @isTest
    static void testEnqueueWithNoMatchingRecords() {
        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(90));
        Test.stopTest();

        System.assertEquals(true, results[0].success, 'Job should be enqueued');
        System.assertNotEquals(null, results[0].jobId, 'Job Id should be populated');
        System.assertEquals(SETUP_RECORD_COUNT, [SELECT COUNT() FROM RecordAccessLog__c],
            'All records should remain (none older than threshold in test context)');
    }

    /**
     * @description Threshold of 0 enqueues a job; records created "today" are not older than the
     *              cutoff, so nothing is deleted.
     */
    @isTest
    static void testZeroDaysThreshold() {
        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(0));
        Test.stopTest();

        System.assertEquals(true, results[0].success, 'Job should be enqueued');
        System.assertEquals(SETUP_RECORD_COUNT, [SELECT COUNT() FROM RecordAccessLog__c],
            'Records created today should not be deleted with a 0-day threshold');
    }

    /**
     * @description A large threshold enqueues a job and deletes nothing.
     */
    @isTest
    static void testLargeThreshold() {
        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(3650));
        Test.stopTest();

        System.assertEquals(true, results[0].success, 'Job should be enqueued');
        System.assertEquals(SETUP_RECORD_COUNT, [SELECT COUNT() FROM RecordAccessLog__c],
            'All records should remain');
    }

    /**
     * @description Negative threshold fails validation and does NOT enqueue a batch job.
     */
    @isTest
    static void testNegativeThreshold() {
        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(-1));
        Test.stopTest();

        System.assertEquals(false, results[0].success, 'Operation should fail validation');
        System.assertEquals(null, results[0].jobId, 'No job should be enqueued');
        System.assertNotEquals(null, results[0].errorMessage, 'Should have an error message');
        System.assertEquals(0, batchJobCount(), 'No batch job should have been enqueued');
    }

    /**
     * @description Null threshold fails validation and does NOT enqueue a batch job.
     */
    @isTest
    static void testNullThreshold() {
        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(null));
        Test.stopTest();

        System.assertEquals(false, results[0].success, 'Operation should fail validation');
        System.assertEquals(null, results[0].jobId, 'No job should be enqueued');
        System.assertNotEquals(null, results[0].errorMessage, 'Should have an error message');
        System.assertEquals(0, batchJobCount(), 'No batch job should have been enqueued');
    }

    /**
     * @description Mixed batch of requests: the valid one is enqueued, the invalid one fails,
     *              processed independently in a single invocation.
     */
    @isTest
    static void testMultipleRequests() {
        List<DeleteOldRecordAccessLogs.CleanupRequest> requests =
            new List<DeleteOldRecordAccessLogs.CleanupRequest>{
                buildRequest(90),   // valid
                buildRequest(-5)    // invalid
            };

        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results =
            DeleteOldRecordAccessLogs.deleteOldRecords(requests);
        Test.stopTest();

        System.assertEquals(2, results.size(), 'Should return two results');

        System.assertEquals(true, results[0].success, 'First (valid) request should be enqueued');
        System.assertNotEquals(null, results[0].jobId, 'First request should have a Job Id');

        System.assertEquals(false, results[1].success, 'Second (invalid) request should fail');
        System.assertEquals(null, results[1].jobId, 'Second request should not enqueue a job');

        System.assertEquals(1, batchJobCount(), 'Only the valid request should enqueue a batch job');
    }

    /**
     * @description When there are no records at all, the job still enqueues and runs cleanly.
     */
    @isTest
    static void testNoRecords() {
        delete [SELECT Id FROM RecordAccessLog__c];
        System.assertEquals(0, [SELECT COUNT() FROM RecordAccessLog__c], 'Should have 0 records');

        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(30));
        Test.stopTest();

        System.assertEquals(true, results[0].success, 'Job should be enqueued');
        System.assertNotEquals(null, results[0].jobId, 'Job Id should be populated');
        System.assertEquals(0, [SELECT COUNT() FROM RecordAccessLog__c], 'Still 0 records');
    }

    /**
     * @description Exercises the global programmatic entry point that subscribers of the managed
     *              package use: constructing the batch via the global constructor and running it
     *              directly with Database.executeBatch (bypassing the invocable method).
     */
    @isTest
    static void testBatchViaGlobalConstructor() {
        List<RecordAccessLog__c> allLogs = [SELECT Id FROM RecordAccessLog__c ORDER BY CreatedDate ASC];
        System.assert(allLogs.size() >= 2, 'Expected at least 2 records from setup');

        Test.setCreatedDate(allLogs[0].Id, DateTime.now().addDays(-120));
        Test.setCreatedDate(allLogs[1].Id, DateTime.now().addDays(-45));
        Set<Id> oldIds = new Set<Id>{ allLogs[0].Id, allLogs[1].Id };

        Integer initialCount = [SELECT COUNT() FROM RecordAccessLog__c];

        Test.startTest();
        Id jobId = Database.executeBatch(new DeleteOldRecordAccessLogs(30), 2000);
        Test.stopTest(); // batch executes here

        System.assertNotEquals(null, jobId, 'executeBatch should return a job Id');

        Integer remaining = [SELECT COUNT() FROM RecordAccessLog__c];
        System.assertEquals(initialCount - 2, remaining, 'The two old records should be deleted');

        Integer stillLive = [SELECT COUNT() FROM RecordAccessLog__c WHERE Id IN :oldIds];
        System.assertEquals(0, stillLive, 'The two old records should no longer be live');

        System.assertEquals(2, DeleteOldRecordAccessLogs.softDeletedThisTransaction,
            'Both old records should have been soft-deleted by the batch');
        System.assertEquals(2, DeleteOldRecordAccessLogs.hardDeletedThisTransaction,
            'Both deleted records should have been hard-deleted (purged from the Recycle Bin)');
    }
}
