/**
 * @description Test class for TrxSec_DetectTotalAccessReportExport
 */
@isTest
private class TrxSec_DetectTotalAccessReportExportTest {
    
    /**
     * Test that policy returns false when user has accessed fewer records than threshold
     */
    @isTest
    static void testBelowThreshold() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create RecordAccessLog records below threshold with aggregate counts
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        Datetime accessTime = Datetime.now();
        
        // Simulate 5 access events, each counting 100 records = 500 total (below 10k threshold)
        for (Integer i = 0; i < 5; i++) {
            logs.add(new RecordAccessLog__c(
                User__c = testUser.Id,
                Count_of_Records__c = 100,
                AccessTime__c = accessTime
            ));
        }
        insert logs;
        
        // Create test reportEvent
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false (allowed) when below threshold
        System.assertEquals(false, result, 'Policy should return false when below threshold');
    }
    
    /**
     * Test that policy returns true when user has accessed more than threshold records
     * Uses aggregate Count_of_Records__c for efficient storage
     */
    @isTest
    static void testAboveThreshold() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        Datetime accessTime = Datetime.now();
        
        Test.startTest();
        // Simulate 11 access events, each counting 1000 records = 11,000 total (above 10k threshold)
        for (Integer i = 0; i < 11; i++) {
            logs.add(new RecordAccessLog__c(
                User__c = testUser.Id,
                Count_of_Records__c = 1000,
                AccessTime__c = accessTime
            ));
        }
        insert logs;
        
        // Create test reportEvent
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        
        // Evaluate the policy
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return true (blocked) when above threshold (11 * 1000 = 11,000 total)
        System.assertEquals(true, result, 'Policy should return true when above threshold');
    }
    
    /**
     * Test that policy only counts records within 24-hour window
     */
    @isTest
    static void testTimeWindow() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        Datetime now = Datetime.now();
        Datetime within24Hours = now.addHours(-23);
        Datetime outside24Hours = now.addHours(-25);
        
        // Record within the 24-hour window (1000 records). CreatedDate defaults to now (insert time).
        RecordAccessLog__c withinWindow = new RecordAccessLog__c(
            User__c = testUser.Id,
            Count_of_Records__c = 1000,
            AccessTime__c = within24Hours
        );
        insert withinWindow;
        
        // Record outside the 24-hour window (should not be counted). The policy now filters on
        // CreatedDate, which cannot be set via DML, so we backdate it with Test.setCreatedDate.
        RecordAccessLog__c outsideWindow = new RecordAccessLog__c(
            User__c = testUser.Id,
            Count_of_Records__c = 20000,
            AccessTime__c = outside24Hours
        );
        insert outsideWindow;
        Test.setCreatedDate(outsideWindow.Id, outside24Hours);
        
        // Create test reportEvent
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = now;
        testEvent.Operation = 'ReportExported';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false because only 1000 records are within window
        System.assertEquals(false, result, 'Policy should only count records within 24-hour window');
    }
    
    /**
     * Test that policy sums all aggregate counts
     */
    @isTest
    static void testDuplicateRecordIds() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create multiple access logs with aggregate counts
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        Datetime accessTime = Datetime.now();
        
        // Create 5 logs, each counting 100 records = 500 total (below threshold)
        for (Integer i = 0; i < 5; i++) {
            logs.add(new RecordAccessLog__c(
                User__c = testUser.Id,
                Count_of_Records__c = 100,
                AccessTime__c = accessTime.addMinutes(i)
            ));
        }
        insert logs;
        
        // Create test reportEvent
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false because only 500 total records
        System.assertEquals(false, result, 'Policy should sum all aggregate counts');
    }
    
    /**
     * Test that policy returns false when Operation is not an export operation
     */
    @isTest
    static void testNonReportExportedOperation() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create RecordAccessLog records above threshold with aggregate counts
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        Datetime accessTime = Datetime.now();
        
        // Simulate 15 access events, each counting 1000 records = 15,000 total (above 10k threshold)
        for (Integer i = 0; i < 15; i++) {
            logs.add(new RecordAccessLog__c(
                User__c = testUser.Id,
                Count_of_Records__c = 1000,
                AccessTime__c = accessTime
            ));
        }
        insert logs;
        
        // Create test reportEvent with a real non-export Operation picklist value. 'ReportViewed'
        // was used here previously, but that value is not in the ReportEvent.Operation picklist, so
        // it could not distinguish a correct guard from one that rejects unknown strings by accident.
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportRunFromLightning';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false when the operation is not an export
        System.assertEquals(false, result, 'Policy should return false when operation is not an export');
    }
    
    /**
     * Test that policy returns false when Operation is null
     */
    @isTest
    static void testNullOperation() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create test reportEvent with null Operation
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = null;
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false when Operation is null
        System.assertEquals(false, result, 'Policy should return false when Operation is null');
    }
    
    /**
     * Test that policy returns false when no records exist for user
     */
    @isTest
    static void testNoRecordsForUser() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Don't create any RecordAccessLog records
        
        // Create test reportEvent
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false when no records exist
        System.assertEquals(false, result, 'Policy should return false when no records exist for user');
    }
    
    /**
     * Test that policy correctly handles exactly at threshold (10,000 records)
     */
    @isTest
    static void testExactlyAtThreshold() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create exactly 10,000 using aggregate counts (at threshold, not above)
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        Datetime accessTime = Datetime.now();
        
        Test.startTest();
        for (Integer i = 0; i < 10; i++) {
            logs.add(new RecordAccessLog__c(
                User__c = testUser.Id,
                Count_of_Records__c = 1000,
                AccessTime__c = accessTime
            ));
        }
        insert logs;
        
        // Create test reportEvent
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        
        // Evaluate the policy
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false when exactly at threshold (> not >=)
        System.assertEquals(false, result, 'Policy should return false when exactly at threshold');
    }
    
    /**
     * Test that policy can be instantiated multiple times
     */
    @isTest
    static void testMultipleInstantiations() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create test event
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        
        // Create multiple policy instances
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy1 = new TrxSec_DetectTotalAccessReportExport();
        TrxSec_DetectTotalAccessReportExport policy2 = new TrxSec_DetectTotalAccessReportExport();
        
        Boolean result1 = policy1.evaluate(testEvent);
        Boolean result2 = policy2.evaluate(testEvent);
        Test.stopTest();
        
        // Both should return false with no data
        System.assertEquals(false, result1, 'First policy evaluation should work');
        System.assertEquals(false, result2, 'Second policy evaluation should work');
    }
    
    /**
     * REGRESSION TEST for the total-access threshold defect.
     *
     * With zero prior history, a single report export of 10,001 records must trip the threshold.
     * Before the fix the count for the event being evaluated was only published as a Platform Event
     * and summed on a LATER evaluation, so this returned false and a fresh 24-hour window allowed an
     * unbounded single-export extraction. This test fails against the pre-fix code.
     */
    @isTest
    static void testCurrentEventAloneCrossesThreshold() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        // No RecordAccessLog__c rows at all: the historical sum is null.
        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        testEvent.Records = '{"totalSize":10001,"rows":[{"datacells":["001000000000001AAA"]}]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();

        System.assertEquals(
            true,
            result,
            'A single 10,001-record export with no prior history must trip the threshold'
        );
    }

    /**
     * Boundary: exactly 10,000 records in the current event with no history stays allowed, because
     * the comparison is strictly greater than.
     */
    @isTest
    static void testCurrentEventExactlyAtThreshold() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        testEvent.Records = '{"totalSize":10000,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();

        System.assertEquals(
            false,
            result,
            'Exactly 10,000 records must not trip the threshold (comparison is > not >=)'
        );
    }

    /**
     * History of 9,000 plus a current event of 1,500 crosses only when combined. Neither number
     * alone exceeds 10,000, so this only passes if the current event is actually being added.
     */
    @isTest
    static void testHistoryPlusCurrentEventCrossesThreshold() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        insert new RecordAccessLog__c(
            User__c = testUser.Id,
            Count_of_Records__c = 9000,
            AccessTime__c = Datetime.now(),
            Event_Type__c = 'ReportEvent'
        );

        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        testEvent.Records = '{"totalSize":1500,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();

        System.assertEquals(
            true,
            result,
            '9,000 historical plus 1,500 current records must trip the threshold'
        );
    }

    /**
     * A blank, null or malformed Records payload must not throw out of evaluate() and must fall back
     * to the historical-only comparison. An exception escaping a TSP condition has unpredictable
     * enforcement consequences.
     */
    @isTest
    static void testMalformedRecordsPayloadFallsBackToHistory() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        // 9,500 of history: below the threshold on its own, and no payload can add to it.
        insert new RecordAccessLog__c(
            User__c = testUser.Id,
            Count_of_Records__c = 9500,
            AccessTime__c = Datetime.now(),
            Event_Type__c = 'ReportEvent'
        );

        List<String> unusablePayloads = new List<String>{
            null,
            '',
            '   ',
            '{ "invalid_json": ',
            '[1,2,3]',
            '{"someOtherKey":"someValue"}'
        };

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        for (String payload : unusablePayloads) {
            reportEvent testEvent = new reportEvent();
            testEvent.UserId = testUser.Id;
            testEvent.EventDate = Datetime.now();
            testEvent.Operation = 'ReportExported';
            testEvent.Records = payload;

            Boolean result = policy.evaluate(testEvent);

            System.assertEquals(
                false,
                result,
                'An unusable Records payload should contribute 0 and leave the 9,500 history below ' +
                    'the threshold. Payload: ' + payload
            );
        }
        Test.stopTest();
    }

    /**
     * When a report's data is split across multiple events, every chunk shares one
     * ExecutionIdentifier and carries the SAME RowsProcessed (the total for the whole execution),
     * differing only in Records and Sequence. The condition therefore counts each chunk's own
     * Records payload, never RowsProcessed.
     *
     * If RowsProcessed were added per event, each of these two chunks would independently see
     * 12,000 and report true, so a legitimate 12,000-row export split into N chunks would fire the
     * policy N times on an inflated total. Both chunks must be scored on their own payloads.
     */
    @isTest
    static void testChunkedExportIsNotCountedTwice() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        Datetime now = Datetime.now();
        String executionIdentifier = 'a50a4025-84f2-425d-8af9-2c780869f3b5';

        reportEvent chunkOne = new reportEvent();
        chunkOne.UserId = testUser.Id;
        chunkOne.EventDate = now;
        chunkOne.Operation = 'ReportExported';
        chunkOne.ExecutionIdentifier = executionIdentifier;
        chunkOne.Sequence = 1;
        chunkOne.RowsProcessed = 12000;
        chunkOne.Records = '{"totalSize":6000,"rows":[]}';

        reportEvent chunkTwo = new reportEvent();
        chunkTwo.UserId = testUser.Id;
        chunkTwo.EventDate = now;
        chunkTwo.Operation = 'ReportExported';
        chunkTwo.ExecutionIdentifier = executionIdentifier;
        chunkTwo.Sequence = 2;
        chunkTwo.RowsProcessed = 12000;
        chunkTwo.Records = '{"totalSize":6000,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean resultOne = policy.evaluate(chunkOne);
        Boolean resultTwo = policy.evaluate(chunkTwo);
        Test.stopTest();

        // Each chunk contributes only its own 6,000 rows. With no persisted history yet (the
        // Platform Event for chunk one has not been processed into a log), neither chunk crosses
        // 10,000 on its own. Using the shared RowsProcessed of 12,000 would have made both true.
        System.assertEquals(
            false,
            resultOne,
            'First chunk must be scored on its own 6,000-record payload, not the shared RowsProcessed'
        );
        System.assertEquals(
            false,
            resultTwo,
            'Second chunk must not re-count the execution total; scoring it twice would false positive'
        );
    }

    /**
     * The chunk counting basis is consistent with the persisted history: once chunk one's Platform
     * Event has been turned into a RecordAccessLog__c row by the subscribing Flow, chunk two's own
     * payload adds to it and the combined execution total does cross the threshold exactly once.
     */
    @isTest
    static void testChunkedExportCrossesThresholdOnceHistoryLands() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        Datetime now = Datetime.now();

        // Chunk one already persisted by the Flow, using the same derivation the condition uses.
        insert new RecordAccessLog__c(
            User__c = testUser.Id,
            Count_of_Records__c = LogMultipleRecordAccess.extractRecordCount('{"totalSize":6000,"rows":[]}'),
            AccessTime__c = now,
            Event_Type__c = 'ReportEvent'
        );

        reportEvent chunkTwo = new reportEvent();
        chunkTwo.UserId = testUser.Id;
        chunkTwo.EventDate = now;
        chunkTwo.Operation = 'ReportExported';
        chunkTwo.ExecutionIdentifier = 'a50a4025-84f2-425d-8af9-2c780869f3b5';
        chunkTwo.Sequence = 2;
        chunkTwo.RowsProcessed = 12000;
        chunkTwo.Records = '{"totalSize":6000,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(chunkTwo);
        Test.stopTest();

        System.assertEquals(
            true,
            result,
            '6,000 persisted from chunk one plus 6,000 in chunk two must cross the 10,000 threshold'
        );
    }

    /**
     * The Operation guard runs before any counting, so a non-export operation returns false even
     * when the current event carries a payload far above the threshold.
     */
    @isTest
    static void testNonExportOperationIgnoresCurrentEventCount() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportRunFromLightning';
        testEvent.Records = '{"totalSize":50000,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();

        System.assertEquals(
            false,
            result,
            'Counting must happen after the export guard, so a report merely run never counts'
        );
    }

    /**
     * REGRESSION TEST for the export-operation guard defect.
     *
     * ReportEvent.Operation is a restricted picklist with exactly three export values:
     * ReportExported, ReportExportedAsynchronously and ReportExportedUsingExcelConnector. The guard
     * used to match only 'ReportExported' exactly, so an asynchronous export short-circuited before
     * ever being counted or logged. Salesforce routes large report exports through asynchronous
     * export, so this silently skipped precisely the high-volume exports the policy exists to catch.
     *
     * This test fails against the pre-fix code, which returns false for this event.
     */
    @isTest
    static void testAsynchronousExportIsEvaluated() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExportedAsynchronously';
        testEvent.Records = '{"totalSize":10001,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();

        System.assertEquals(
            true,
            result,
            'ReportExportedAsynchronously must be evaluated, not short-circuited by the guard'
        );
    }

    /**
     * The Excel connector is the third export path and must also be evaluated.
     */
    @isTest
    static void testExcelConnectorExportIsEvaluated() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExportedUsingExcelConnector';
        testEvent.Records = '{"totalSize":10001,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();

        System.assertEquals(
            true,
            result,
            'ReportExportedUsingExcelConnector must be evaluated, not short-circuited by the guard'
        );
    }

    /**
     * The originally handled value must keep behaving exactly as before. A UI export to Excel
     * still reports Operation='ReportExported'; the file format travels in ExportFileFormat, which
     * the guard must not consider.
     */
    @isTest
    static void testPlainExportBehaviourUnchanged() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        reportEvent testEvent = new reportEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        testEvent.Operation = 'ReportExported';
        testEvent.ExportFileFormat = 'Excel';
        testEvent.Records = '{"totalSize":10001,"rows":[]}';

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();

        System.assertEquals(true, result, 'ReportExported must keep being evaluated');
    }

    /**
     * Operation is nillable. The old guard was accidentally null-safe because
     * 'ReportExported'.equals(null) is false; a prefix match on a null value would throw a
     * NullPointerException instead. An exception escaping a TSP condition has unpredictable
     * enforcement consequences, so blank input must return false without throwing.
     */
    @isTest
    static void testBlankOperationReturnsFalseWithoutException() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];

        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        for (String blankOperation : new List<String>{ null, '' }) {
            reportEvent testEvent = new reportEvent();
            testEvent.UserId = testUser.Id;
            testEvent.EventDate = Datetime.now();
            testEvent.Operation = blankOperation;
            testEvent.Records = '{"totalSize":50000,"rows":[]}';

            try {
                System.assertEquals(
                    false,
                    policy.evaluate(testEvent),
                    'A blank Operation must return false. Operation: ' + blankOperation
                );
            } catch (Exception e) {
                System.assert(
                    false,
                    'A blank Operation must not throw out of evaluate(). Operation: ' +
                        blankOperation + ', exception: ' + e.getTypeName() + ' - ' + e.getMessage()
                );
            }
        }
        Test.stopTest();
    }

    /**
     * Test that policy isolates users (one user's records don't affect another)
     */
    @isTest
    static void testUserIsolation() {
        // Create test users
        User testUser1 = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create a second test user (using standard user profile)
        Profile p = [SELECT Id FROM Profile WHERE Name='Standard User' LIMIT 1];
        User testUser2 = new User(
            Alias = 'tuser2',
            Email = 'testuser2@testorg.com',
            EmailEncodingKey = 'UTF-8',
            LastName = 'Testing2',
            LanguageLocaleKey = 'en_US',
            LocaleSidKey = 'en_US',
            ProfileId = p.Id,
            TimeZoneSidKey = 'America/Los_Angeles',
            UserName = 'testuser2' + Datetime.now().getTime() + '@testorg.com'
        );
        insert testUser2;
        
        // Create access logs for both users
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        Datetime accessTime = Datetime.now();
        
        // User1: 1000 records (below threshold)
        logs.add(new RecordAccessLog__c(
            User__c = testUser1.Id,
            Count_of_Records__c = 1000,
            AccessTime__c = accessTime
        ));
        
        // User2: 20,000 records (above threshold, but should not affect user1)
        logs.add(new RecordAccessLog__c(
            User__c = testUser2.Id,
            Count_of_Records__c = 20000,
            AccessTime__c = accessTime
        ));
        insert logs;
        
        // Create test reportEvent for user1
        reportEvent testEvent1 = new reportEvent();
        testEvent1.UserId = testUser1.Id;
        testEvent1.EventDate = Datetime.now();
        testEvent1.Operation = 'ReportExported';
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessReportExport policy = new TrxSec_DetectTotalAccessReportExport();
        Boolean result1 = policy.evaluate(testEvent1);
        Test.stopTest();
        
        // Should return false for user1 (only 1000 records, not user2's 20000)
        System.assertEquals(false, result1, 'Policy should isolate users and only count user1 records');
    }
}

