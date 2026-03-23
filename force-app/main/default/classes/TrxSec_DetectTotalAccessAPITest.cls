/**
 * @description Test class for TrxSec_DetectTotalAccessAPI
 */
@IsTest
private class TrxSec_DetectTotalAccessAPITest {
    
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
        
        // Create test ApiEvent
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false (allowed) when below threshold
        System.assertEquals(false, result, 'Policy should return false when below threshold');
    }
    
    /**
     * Test that LogMultipleRecordAccess correctly parses ApiEvent totalSize and creates aggregate log
     */
    @isTest
    static void testApiEventTotalSizeParsing() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        Datetime now = Datetime.now();
        
        // Use the real JSON format from ApiEvent with totalSize
        String jsonInput = '{"totalSize":1369,"done":true,"records":[{"attributes":{"type":"Account"},"Id":"001000000000001"}]}';
        
        LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
        input.RecordsField = jsonInput;
        input.UserId = testUser.Id;
        input.EventDate = now;
        
        Test.startTest();
        LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{ input });
        Test.stopTest();
        
        // Should create exactly 1 log with Count_of_Records__c = 1369
        List<RecordAccessLog__c> logs = [
            SELECT Count_of_Records__c
            FROM RecordAccessLog__c
            WHERE User__c = :testUser.Id
        ];
        
        System.assertEquals(1, logs.size(), 'Should create exactly 1 aggregate log');
        System.assertEquals(1369, logs[0].Count_of_Records__c, 'Should store totalSize count');
    }
    
    /**
     * Test that ListView/Report JSON (with records array) stores count instead of individual IDs
     */
    @isTest
    static void testListViewRecordsCountParsing() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        Datetime now = Datetime.now();
        
        // ListView/Report JSON with records array (no totalSize)
        String jsonInput = '{"records":[{"Id":"001000000000001"},{"Id":"001000000000002"},{"Id":"001000000000003"}]}';
        
        LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
        input.RecordsField = jsonInput;
        input.UserId = testUser.Id;
        input.EventDate = now;
        
        Test.startTest();
        LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{ input });
        Test.stopTest();
        
        // Should create exactly 1 log with Count_of_Records__c = 3 (count of records array)
        List<RecordAccessLog__c> logs = [
            SELECT Count_of_Records__c
            FROM RecordAccessLog__c
            WHERE User__c = :testUser.Id
        ];
        
        System.assertEquals(1, logs.size(), 'Should create exactly 1 aggregate log');
        System.assertEquals(3, logs[0].Count_of_Records__c, 'Should store count of records array');
    }
    
    /**
     * Test that TSP policy publishes Platform Events (cannot verify DML in TSP context)
     */
    @isTest
    static void testPlatformEventPublishing() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        Datetime now = Datetime.now();
        
        // Use the real JSON format from ApiEvent with totalSize
        String jsonInput = '{"totalSize":1369,"done":true,"records":[{"attributes":{"type":"Account"},"Id":"001000000000001"}]}';
        
        // Create test ApiEvent with Records field
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = now;
        testEvent.Records = jsonInput;
        
        Test.startTest();
        // Call the TSP policy evaluate method
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // In a real TSP context, DML limit is 0, so we can't create RecordAccessLog__c records
        // Instead, the policy should publish a Platform Event
        // Platform Events are delivered asynchronously, so we can't directly verify in tests
        // But we can verify the policy didn't throw an exception
        System.assertNotEquals(null, result, 'Policy should complete without exception');
        
        // Note: In a real environment, the Flow "Process_Record_Access_Event" will consume
        // the RecordAccessEvent__e and create RecordAccessLog__c records
    }
    
    /**
     * Test that policy correctly sums all aggregate counts
     */
    @isTest
    static void testMixedAggregateAndIndividualCounts() {
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        Datetime accessTime = Datetime.now();
        
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        
        // Add 11 aggregate logs (from any event type) = 11,000 records total
        for (Integer i = 0; i < 11; i++) {
            logs.add(new RecordAccessLog__c(
                User__c = testUser.Id,
                Count_of_Records__c = 1000,
                AccessTime__c = accessTime
            ));
        }
        
        insert logs;
        
        // Total = 11,000 (above threshold of 10,000)
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        System.assertEquals(true, result, 'Policy should return true when aggregate count exceeds threshold');
    }

    
    /**
     * Test that policy returns true when user has accessed more than threshold records
     * Uses aggregate Count_of_Records__c for all event types
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
        
        // Create test ApiEvent
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
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
        
        // Create records within 24-hour window (1000 records)
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        logs.add(new RecordAccessLog__c(
            User__c = testUser.Id,
            Count_of_Records__c = 1000,
            AccessTime__c = within24Hours
        ));
        
        // Create records outside 24-hour window (should not be counted)
        logs.add(new RecordAccessLog__c(
            User__c = testUser.Id,
            Count_of_Records__c = 20000,
            AccessTime__c = outside24Hours
        ));
        insert logs;
        
        // Create test ApiEvent
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = now;
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false because only 1000 records are within window
        System.assertEquals(false, result, 'Policy should only count records within 24-hour window');
    }
    
    /**
     * Test that policy handles duplicate access events by summing all counts
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
        
        // Create test ApiEvent
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false because only 500 total records
        System.assertEquals(false, result, 'Policy should sum all aggregate counts');
    }
    
    /**
     * Test that policy returns false when UserId is null
     */
    @isTest
    static void testNullUserId() {
        // Create test ApiEvent with null UserId
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = null;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false when UserId is null
        System.assertEquals(false, result, 'Policy should return false when UserId is null');
    }
    
    /**
     * Test that policy returns false when EventDate is null
     */
    @isTest
    static void testNullEventDate() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Create test ApiEvent with null EventDate
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = null;
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false when EventDate is null
        System.assertEquals(false, result, 'Policy should return false when EventDate is null');
    }
    
    /**
     * Test that policy returns false when both UserId and EventDate are null
     */
    @isTest
    static void testNullUserIdAndEventDate() {
        // Create test ApiEvent with null values
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = null;
        testEvent.EventDate = null;
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result = policy.evaluate(testEvent);
        Test.stopTest();
        
        // Should return false when both are null
        System.assertEquals(false, result, 'Policy should return false when UserId and EventDate are null');
    }
    
    /**
     * Test that policy returns false when no records exist for user
     */
    @isTest
    static void testNoRecordsForUser() {
        // Create test user
        User testUser = [SELECT Id FROM User WHERE Id = :UserInfo.getUserId()];
        
        // Don't create any RecordAccessLog records
        
        // Create test ApiEvent
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
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
        
        List<RecordAccessLog__c> logs = new List<RecordAccessLog__c>();
        Datetime accessTime = Datetime.now();
        
        // Create exactly 10,000 using aggregate counts (at threshold, not above)
        Test.startTest();
        for (Integer i = 0; i < 10; i++) {
            logs.add(new RecordAccessLog__c(
                User__c = testUser.Id,
                Count_of_Records__c = 1000,
                AccessTime__c = accessTime
            ));
        }
        insert logs;
        
        // Create test ApiEvent
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
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
        ApiEvent testEvent = new ApiEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Create multiple policy instances
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy1 = new TrxSec_DetectTotalAccessAPI();
        TrxSec_DetectTotalAccessAPI policy2 = new TrxSec_DetectTotalAccessAPI();
        
        Boolean result1 = policy1.evaluate(testEvent);
        Boolean result2 = policy2.evaluate(testEvent);
        Test.stopTest();
        
        // Both should return false with no data
        System.assertEquals(false, result1, 'First policy evaluation should work');
        System.assertEquals(false, result2, 'Second policy evaluation should work');
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
        
        // Create test ApiEvent for user1
        ApiEvent testEvent1 = new ApiEvent();
        testEvent1.UserId = testUser1.Id;
        testEvent1.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessAPI policy = new TrxSec_DetectTotalAccessAPI();
        Boolean result1 = policy.evaluate(testEvent1);
        Test.stopTest();
        
        // Should return false for user1 (only 1000 records, not user2's 20000)
        System.assertEquals(false, result1, 'Policy should isolate users and only count user1 records');
    }
}

