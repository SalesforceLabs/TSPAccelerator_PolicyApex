/**
 * @description Test class for DeleteOldRecordAccessLogs.
 *
 * The class now runs deletion asynchronously via Batch Apex, so the invocable method only
 * reports whether the job was enqueued (success + jobId); the actual deletion happens when
 * the batch runs at Test.stopTest(). These tests cover enqueue validation, the batch delete
 * path, and verify that deleted rows are hard-deleted (purged from the Recycle Bin).
 *
 * Permission enforcement is covered from both entry points using a restricted user: the
 * invocable, and start() for callers who submit the batch directly via the global constructor.
 * That user's profile is discovered from ObjectPermissions at run time rather than hardcoded,
 * so the tests work against subscriber orgs with arbitrary profile sets. If an org offers no
 * usable profile, those two tests log a warning and skip instead of failing the run.
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
     * @description Profiles tried first when provisioning the restricted user. This is only an
     *              ordering preference, not a requirement: any standard-user-type profile
     *              without Delete on the log object works, and these are simply the least
     *              likely to have side effects. A subscriber org missing all of them still
     *              gets coverage from whatever other qualifying profile it has.
     */
    private static final List<String> PREFERRED_PROFILE_NAMES = new List<String>{
        'Minimum Access - Salesforce',
        'Read Only',
        'Standard Platform User',
        'Standard User'
    };

    // Bounds the work when an org has many profiles whose user licenses are exhausted.
    private static final Integer MAX_PROFILE_ATTEMPTS = 5;

    private static final String NO_PROFILE_MESSAGE =
        'DeleteOldRecordAccessLogsTest: skipped the permission-denial assertions because this org '
        + 'has no assignable profile that lacks Delete on the Record Access Log object. The '
        + 'enforcement itself is unaffected; only this test\'s coverage of it was skipped.';

    /**
     * @description Profiles that do NOT grant Delete on the log object, most-preferred first.
     *              Derived from ObjectPermissions rather than profile names so it holds up in
     *              subscriber orgs with custom profiles. A profile with no ObjectPermissions
     *              row for the object grants no access at all, so it correctly qualifies.
     *              The object name is resolved via describe so the managed-package namespace
     *              prefix is picked up in subscriber orgs.
     */
    private static List<Profile> profilesWithoutDeleteAccess() {
        String logObjectName = RecordAccessLog__c.SObjectType.getDescribe().getName();

        Set<Id> profilesWithDelete = new Set<Id>();
        for (ObjectPermissions op : [
            SELECT Parent.ProfileId
            FROM ObjectPermissions
            WHERE SobjectType = :logObjectName
              AND PermissionsDelete = true
              AND Parent.IsOwnedByProfile = true
        ]) {
            profilesWithDelete.add(op.Parent.ProfileId);
        }

        Map<String, Profile> candidatesByName = new Map<String, Profile>();
        for (Profile p : [SELECT Id, Name FROM Profile WHERE UserType = 'Standard']) {
            if (!profilesWithDelete.contains(p.Id)) {
                candidatesByName.put(p.Name, p);
            }
        }

        List<Profile> ordered = new List<Profile>();
        for (String preferredName : PREFERRED_PROFILE_NAMES) {
            if (candidatesByName.containsKey(preferredName)) {
                ordered.add(candidatesByName.remove(preferredName));
            }
        }
        ordered.addAll(candidatesByName.values());
        return ordered;
    }

    private static User buildUser(Id profileId) {
        String unique = UserInfo.getOrganizationId()
            + String.valueOf(DateTime.now().getTime())
            + String.valueOf(Integer.valueOf(Math.rint(Math.random() * 1000000)));

        return new User(
            FirstName = 'Restricted',
            LastName = 'Access',
            Alias = 'restrct',
            Email = 'restricted.access@tsptest.invalid',
            Username = unique + '@tsptest.invalid',
            ProfileId = profileId,
            EmailEncodingKey = 'UTF-8',
            LanguageLocaleKey = 'en_US',
            LocaleSidKey = 'en_US',
            TimeZoneSidKey = 'America/Los_Angeles'
        );
    }

    /**
     * @description Provisions a user who cannot delete RecordAccessLog__c, or returns null if
     *              this org offers no usable profile. Callers must treat null as "skip", so a
     *              subscriber org with an unusual profile set does not fail the run.
     *
     *              Each candidate is inserted inside a runAs block on the current user so the
     *              setup-object DML cannot collide with RecordAccessLog__c DML elsewhere in the
     *              transaction (MIXED_DML_OPERATION), and the insert is guarded because a
     *              profile whose user licenses are exhausted throws rather than returning an
     *              error. The chosen user's lack of access is then confirmed directly, so a
     *              profile that turns out to grant Delete is passed over instead of producing a
     *              test that passes for the wrong reason.
     */
    private static User createUserWithoutDeleteAccess() {
        List<Profile> candidates = profilesWithoutDeleteAccess();
        Integer attempts = Math.min(candidates.size(), MAX_PROFILE_ATTEMPTS);

        for (Integer i = 0; i < attempts; i++) {
            User candidate = buildUser(candidates[i].Id);

            try {
                System.runAs(new User(Id = UserInfo.getUserId())) {
                    insert candidate;
                }
            } catch (Exception e) {
                continue;
            }

            Boolean lacksDelete = false;
            System.runAs(candidate) {
                lacksDelete = !Schema.SObjectType.RecordAccessLog__c.isDeletable();
            }
            if (lacksDelete) {
                return candidate;
            }
        }

        return null;
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
     * @description Threshold of 0 would delete every record created before today, so it fails
     *              validation and does NOT enqueue a batch job.
     */
    @isTest
    static void testZeroDaysThreshold() {
        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(0));
        Test.stopTest();

        System.assertEquals(false, results[0].success, 'A 0-day threshold should fail validation');
        System.assertEquals(null, results[0].jobId, 'No job should be enqueued');
        System.assertNotEquals(null, results[0].errorMessage, 'Should have an error message');
        System.assertEquals(0, batchJobCount(), 'No batch job should have been enqueued');
        System.assertEquals(SETUP_RECORD_COUNT, [SELECT COUNT() FROM RecordAccessLog__c],
            'No records should be deleted');
    }

    /**
     * @description The smallest accepted threshold (1) still enqueues a job.
     */
    @isTest
    static void testMinimumValidThreshold() {
        Test.startTest();
        List<DeleteOldRecordAccessLogs.CleanupResult> results = invoke(buildRequest(1));
        Test.stopTest();

        System.assertEquals(true, results[0].success, 'A 1-day threshold should be accepted');
        System.assertNotEquals(null, results[0].jobId, 'Job Id should be populated');
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

    /**
     * @description A user without Delete on RecordAccessLog__c is refused by the invocable with
     *              an otherwise-valid threshold, and no batch job is enqueued on their behalf.
     */
    @isTest
    static void testInvocableDeniedForUserWithoutDeletePermission() {
        User restrictedUser = createUserWithoutDeleteAccess();
        if (restrictedUser == null) {
            System.debug(LoggingLevel.WARN, NO_PROFILE_MESSAGE);
            return;
        }

        List<DeleteOldRecordAccessLogs.CleanupResult> results;
        Test.startTest();
        System.runAs(restrictedUser) {
            // Guards against a false pass: if the profile ever gains Delete, the denial
            // assertions below would pass for the wrong reason.
            System.assertEquals(false, Schema.SObjectType.RecordAccessLog__c.isDeletable(),
                'Precondition: the restricted user must not have Delete on RecordAccessLog__c');

            results = invoke(buildRequest(30));
        }
        Test.stopTest();

        System.assertEquals(1, results.size(), 'Should return one result');
        System.assertEquals(false, results[0].success,
            'An unauthorized caller should be refused even with a valid threshold');
        System.assertEquals(null, results[0].jobId, 'No job should be enqueued');
        System.assertNotEquals(null, results[0].errorMessage, 'Should have an error message');
        System.assertEquals(0, batchJobCount(), 'No batch job should have been enqueued');
        System.assertEquals(SETUP_RECORD_COUNT, [SELECT COUNT() FROM RecordAccessLog__c],
            'No records should have been deleted');
    }

    /**
     * @description An unauthorized caller who skips the invocable and submits the batch directly
     *              via the global constructor is stopped in start(), before any chunk runs.
     *              start() is called directly so the guard is asserted deterministically rather
     *              than relying on how the platform surfaces a failed async job in a test.
     */
    @isTest
    static void testBatchStartDeniedForUserWithoutDeletePermission() {
        User restrictedUser = createUserWithoutDeleteAccess();
        if (restrictedUser == null) {
            System.debug(LoggingLevel.WARN, NO_PROFILE_MESSAGE);
            return;
        }

        Test.startTest();
        System.runAs(restrictedUser) {
            System.assertEquals(false, Schema.SObjectType.RecordAccessLog__c.isDeletable(),
                'Precondition: the restricted user must not have Delete on RecordAccessLog__c');

            Boolean threw = false;
            try {
                new DeleteOldRecordAccessLogs(30).start(null);
            } catch (DeleteOldRecordAccessLogs.DeleteOldRecordAccessLogsException e) {
                threw = true;
                System.assert(e.getMessage().contains('Insufficient access'),
                    'Exception should explain the access failure, got: ' + e.getMessage());
            }
            System.assertEquals(true, threw,
                'start() should throw for a user without Delete on RecordAccessLog__c');
        }
        Test.stopTest();

        System.assertEquals(SETUP_RECORD_COUNT, [SELECT COUNT() FROM RecordAccessLog__c],
            'No records should have been deleted');
    }

    /**
     * @description Positive control for the two denial tests: the same guard permits a user who
     *              does hold Delete, so the tests above are proving permission enforcement and
     *              not merely that the code path always fails.
     */
    @isTest
    static void testBatchStartAllowedForUserWithDeletePermission() {
        System.assertEquals(true, Schema.SObjectType.RecordAccessLog__c.isDeletable(),
            'Precondition: the test-running user should have Delete on RecordAccessLog__c');

        Test.startTest();
        Database.QueryLocator locator = new DeleteOldRecordAccessLogs(30).start(null);
        Test.stopTest();

        System.assertNotEquals(null, locator, 'start() should return a QueryLocator');
    }
}
