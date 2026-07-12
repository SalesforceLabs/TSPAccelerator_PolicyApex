/**
 * @description Test class for TrxSec_DetectTotalAccessListView
 */
@isTest
private class TrxSec_DetectTotalAccessListViewTest {
    
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
        
        // Create test ListViewEvent
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        
        // Create test ListViewEvent
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        
        // Create test ListViewEvent
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = now;
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        
        // Create test ListViewEvent
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        // Create test ListViewEvent with null UserId
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = null;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        
        // Create test ListViewEvent with null EventDate
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = null;
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        // Create test ListViewEvent with null values
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = null;
        testEvent.EventDate = null;
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        
        // Create test ListViewEvent
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        
        // Create test ListViewEvent
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Evaluate the policy
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
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
        ListViewEvent testEvent = new ListViewEvent();
        testEvent.UserId = testUser.Id;
        testEvent.EventDate = Datetime.now();
        
        // Create multiple policy instances
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy1 = new TrxSec_DetectTotalAccessListView();
        TrxSec_DetectTotalAccessListView policy2 = new TrxSec_DetectTotalAccessListView();
        
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
        
        // Create test ListViewEvent for user1
        ListViewEvent testEvent1 = new ListViewEvent();
        testEvent1.UserId = testUser1.Id;
        testEvent1.EventDate = Datetime.now();
        
        // Evaluate the policy
        Test.startTest();
        TrxSec_DetectTotalAccessListView policy = new TrxSec_DetectTotalAccessListView();
        Boolean result1 = policy.evaluate(testEvent1);
        Test.stopTest();
        
        // Should return false for user1 (only 1000 records, not user2's 20000)
        System.assertEquals(false, result1, 'Policy should isolate users and only count user1 records');
    }
}

