/**
 * @description Test class for LogMultipleRecordAccess invocable method
 */
@isTest
private class LogMultipleRecordAccessTest {
    
    /**
     * Setup method to create test user and assign permission set
     */
    @TestSetup
    static void setupTestData() {
        // Create a test user
        Profile p = [SELECT Id FROM Profile WHERE Name = 'Standard User' LIMIT 1];
        User testUser = new User(
            Alias = 'tsptest',
            Email = 'tsptest@test.com',
            EmailEncodingKey = 'UTF-8',
            LastName = 'Testing',
            LanguageLocaleKey = 'en_US',
            LocaleSidKey = 'en_US',
            ProfileId = p.Id,
            TimeZoneSidKey = 'America/Los_Angeles',
            UserName = 'tsptest' + DateTime.now().getTime() + '@test.com'
        );
        insert testUser;
        
        // Query the permission set
        PermissionSet ps = [SELECT Id FROM PermissionSet WHERE Name = 'TSP_Accelerator' LIMIT 1];
        
        // Assign permission set to test user
        PermissionSetAssignment psa = new PermissionSetAssignment(
            PermissionSetId = ps.Id,
            AssigneeId = testUser.Id
        );
        insert psa;
    }
    
    /**
     * Test logging records from Format 1: {"records": [{"Id": "..."}, ...]}
     * This format is typical for ReportEvents or certain API responses
     */
    @isTest
    static void testLogAccess_Format1_RecordsList() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // Create a mock JSON string representing the records list format
            String recordId1 = '001000000000001AAA';
            String recordId2 = '001000000000002AAA';
            String jsonInput = '{"records": [{"Id": "' + recordId1 + '"}, {"Id": "' + recordId2 + '"}]}';
            
            // Prepare input wrapper
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = jsonInput;
            input.UserId = testUser.Id;
            input.EventDate = Datetime.now();
            
            // Run the method
            Test.startTest();
            LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{input});
            Test.stopTest();
            
            // Verify logs were created - now stores aggregate count instead of individual IDs
            List<RecordAccessLog__c> logs = [SELECT Id, Count_of_Records__c, User__c, AccessTime__c FROM RecordAccessLog__c];
            System.assertEquals(1, logs.size(), 'Should create 1 aggregate log for 2 records');
            
            // Verify aggregate count
            System.assertEquals(2, logs[0].Count_of_Records__c, 'Should store count of 2 records');
            System.assertEquals(testUser.Id, logs[0].User__c, 'User ID should match');
        }
    }
    
    /**
     * Test logging records from Format 2: {"rows": [{"datacells": ["...", "..."]}]}
     * This format is typical for ListViewEvents
     */
    @isTest
    static void testLogAccess_Format2_RowsDatacells() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // Create a mock JSON string representing the rows/datacells format
            // Includes one valid ID (length >= 15) and one invalid (short) string to test filtering
            String validRecordId = '001000000000003AAA';
            String shortString = 'NotAnId';
            String jsonInput = '{"rows": [{"datacells": ["' + validRecordId + '", "' + shortString + '"]}]}';
            
            // Prepare input wrapper
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = jsonInput;
            input.UserId = testUser.Id;
            input.EventDate = Datetime.now();
            
            // Run the method
            Test.startTest();
            LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{input});
            Test.stopTest();
            
            // Verify logs were created - now stores aggregate count instead of individual IDs
            List<RecordAccessLog__c> logs = [SELECT Id, Count_of_Records__c FROM RecordAccessLog__c];
            System.assertEquals(1, logs.size(), 'Should create 1 aggregate log (filtering out short string)');
            System.assertEquals(1, logs[0].Count_of_Records__c, 'Should count 1 valid record ID');
        }
    }
    
    /**
     * Test behavior with invalid JSON input
     * Should handle exception gracefully and not create logs
     */
    @isTest
    static void testLogAccess_InvalidJson() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // Prepare input wrapper with invalid JSON
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = '{ "invalid_json": '; // Malformed
            input.UserId = testUser.Id;
            input.EventDate = Datetime.now();
            
            // Run the method
            Test.startTest();
            LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{input});
            Test.stopTest();
            
            // Verify no logs were created
            List<RecordAccessLog__c> logs = [SELECT Id FROM RecordAccessLog__c];
            System.assertEquals(0, logs.size(), 'Should not create logs for invalid JSON');
        }
    }
    
    /**
     * Test behavior with JSON that parses but has unexpected structure (no 'records' or 'rows')
     */
    @isTest
    static void testLogAccess_UnexpectedStructure() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // JSON valid but missing expected keys
            String jsonInput = '{"someOtherKey": "someValue"}';
            
            // Prepare input wrapper
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = jsonInput;
            input.UserId = testUser.Id;
            input.EventDate = Datetime.now();
            
            // Run the method
            Test.startTest();
            LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{input});
            Test.stopTest();
            
            // Verify no logs were created
            List<RecordAccessLog__c> logs = [SELECT Id FROM RecordAccessLog__c];
            System.assertEquals(0, logs.size(), 'Should not create logs for unexpected structure');
        }
    }
    
    /**
     * Test handling of null record IDs in input
     */
    @isTest
    static void testLogAccess_NullRecordIds() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // JSON with null ID in Format 1 - array still has 1 element
            String jsonInput = '{"records": [{"Id": null}]}';
            
            // Prepare input wrapper
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = jsonInput;
            input.UserId = testUser.Id;
            input.EventDate = Datetime.now();
            
            // Run the method
            Test.startTest();
            LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{input});
            Test.stopTest();
            
            // Now that we store aggregate counts, a records array with 1 element creates a log with count=1
            List<RecordAccessLog__c> logs = [SELECT Id, Count_of_Records__c FROM RecordAccessLog__c];
            System.assertEquals(1, logs.size(), 'Should create 1 aggregate log for records array');
            System.assertEquals(1, logs[0].Count_of_Records__c, 'Should count the array size (1)');
        }
    }
    
    /**
     * Test handling of empty input list
     */
    @isTest
    static void testLogAccess_EmptyList() {
        Test.startTest();
        LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>());
        Test.stopTest();
        
        List<RecordAccessLog__c> logs = [SELECT Id FROM RecordAccessLog__c];
        System.assertEquals(0, logs.size(), 'Should not create logs for empty input');
    }
}

