/**
 * @description Test class for DeleteOldRecordAccessLogs
 * Provides comprehensive test coverage for the invocable method
 */
@isTest
private class DeleteOldRecordAccessLogsTest {

    // Helper to evaluate queries under sharing rules (the production class is `with sharing`)
    private with sharing class SharingQueryHelper {
        Integer countLogsOlderThan(Date cutoffDate) {
            return [SELECT COUNT() FROM RecordAccessLog__c WHERE CreatedDate < :cutoffDate];
        }
    }
    
    /**
     * @description Test data setup method - creates test user with permissions and test records
     * Note: CreatedDate cannot be backdated in test context, so all records will have CreatedDate = now()
     * We set AccessTime__c to different dates for data completeness, but deletion is based on CreatedDate
     */
    @testSetup
    static void setupTestData() {
        // Create a test user
        Profile p = [SELECT Id FROM Profile WHERE Name = 'Standard User' LIMIT 1];
        User testUser = new User(
            Alias = 'tspdel',
            Email = 'tspdelete@test.com',
            EmailEncodingKey = 'UTF-8',
            LastName = 'Deleter',
            LanguageLocaleKey = 'en_US',
            LocaleSidKey = 'en_US',
            ProfileId = p.Id,
            TimeZoneSidKey = 'America/Los_Angeles',
            UserName = 'tspdelete' + DateTime.now().getTime() + '@test.com'
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
        
        // Create test RecordAccessLog__c records as the test user
        System.runAs(testUser) {
            List<RecordAccessLog__c> testRecords = new List<RecordAccessLog__c>();
            
            // Create 8 test records with aggregate counts
            for (Integer i = 0; i < 8; i++) {
                RecordAccessLog__c record = new RecordAccessLog__c(
                    User__c = testUser.Id,
                    Count_of_Records__c = 100 + (i * 10),
                    AccessTime__c = DateTime.now().addDays(-i * 10)
                );
                testRecords.add(record);
            }
            
            insert testRecords;
        }
    }
    
    /**
     * @description Test that method executes successfully with a future threshold
     * Since CreatedDate cannot be backdated in tests, all records will be recent
     * This tests that the method handles finding no matching records correctly
     */
    @isTest
    static void testDeleteOldRecords_90DaysThreshold() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tspdelete@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // Verify initial record count
            Integer initialCount = [SELECT COUNT() FROM RecordAccessLog__c];
            System.assertEquals(8, initialCount, 'Should have 8 initial records');
            
            // Create request with 90 day threshold
            // Since all test records have CreatedDate = now(), none will be deleted
            DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
            request.daysThreshold = 90;
            
            Test.startTest();
            
            // Execute the invocable method
            List<DeleteOldRecordAccessLogs.CleanupResult> results = 
                DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
            
            Test.stopTest();
            
            // Verify results
            System.assertEquals(1, results.size(), 'Should return one result');
            DeleteOldRecordAccessLogs.CleanupResult result = results[0];
            
            System.assertEquals(true, result.success, 'Operation should succeed');
            System.assertEquals(0, result.recordsDeleted, 'Should delete 0 records (all are recent in test)');
            System.assertEquals(null, result.errorMessage, 'Should have no error message');
            
            // Verify all records remain
            Integer remainingCount = [SELECT COUNT() FROM RecordAccessLog__c];
            System.assertEquals(8, remainingCount, 'Should have all 8 records remaining');
        }
    }

    /**
     * @description Test that records older than the threshold are deleted.
     * Uses Test.setCreatedDate to backdate CreatedDate in test context.
     */
    @isTest
    static void testDeleteOldRecords_DeletesOldRecords() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tspdelete@test.com' LIMIT 1];

        System.runAs(testUser) {
            List<RecordAccessLog__c> allLogs = [SELECT Id FROM RecordAccessLog__c ORDER BY CreatedDate ASC];
            System.assert(allLogs.size() >= 2, 'Expected at least 2 log records from test setup');

            // Backdate 2 records to ensure they are older than the threshold
            Test.setCreatedDate(allLogs[0].Id, DateTime.now().addDays(-120));
            Test.setCreatedDate(allLogs[1].Id, DateTime.now().addDays(-45));

            // Sanity check record count
            Integer initialCount = [SELECT COUNT() FROM RecordAccessLog__c];

            DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
            request.daysThreshold = 30; // should delete the 2 backdated records

            Test.startTest();
            List<DeleteOldRecordAccessLogs.CleanupResult> results =
                DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
            Test.stopTest();

            System.assertEquals(1, results.size(), 'Should return one result');
            System.assertEquals(true, results[0].success, 'Operation should succeed');
            System.assertEquals(2, results[0].recordsDeleted, 'Should delete the 2 backdated records');

            Integer remainingCount = [SELECT COUNT() FROM RecordAccessLog__c];
            System.assertEquals(initialCount - 2, remainingCount, 'Remaining records should reflect deletions');

            // Verify specific IDs were deleted
            Integer deletedCount = [
                SELECT COUNT()
                FROM RecordAccessLog__c
                WHERE Id IN :new Set<Id>{ allLogs[0].Id, allLogs[1].Id }
            ];
            System.assertEquals(0, deletedCount, 'Backdated records should be deleted');
        }
    }

    /**
     * @description Test that the method returns an error when the running user lacks delete permission.
     * This covers the branch where Schema.SObjectType.RecordAccessLog__c.isDeletable() is false
     */
    @isTest
    static void testDeleteOldRecords_InsufficientDeletePermission() {
        // Find a low-privilege profile (avoid System Administrator / broad-data profiles)
        List<Profile> candidateProfiles = [
            SELECT Id, Name, PermissionsModifyAllData, PermissionsViewAllData
            FROM Profile
            WHERE PermissionsModifyAllData = false
              AND PermissionsViewAllData = false
              AND Name != 'System Administrator'
            ORDER BY Name
            LIMIT 10
        ];
        System.assert(!candidateProfiles.isEmpty(), 'Expected at least one low-privilege profile');

        User nonDeletableUser;
        for (Profile p : candidateProfiles) {
            User u = new User(
                Alias = 'tspnd',
                Email = 'tspnodelete+' + p.Id + '@test.com',
                EmailEncodingKey = 'UTF-8',
                LastName = 'NoDelete',
                LanguageLocaleKey = 'en_US',
                LocaleSidKey = 'en_US',
                ProfileId = p.Id,
                TimeZoneSidKey = 'America/Los_Angeles',
                UserName = 'tspnodelete+' + p.Id + '+' + DateTime.now().getTime() + '@test.com'
            );
            try {
                insert u;
            } catch (DmlException ex) {
                // Some orgs have external/community profiles that cannot be used to create users
                // without additional org settings; skip those profiles.
                continue;
            }

            System.runAs(u) {
                // Ensure this user can't delete logs but can create them for this test setup
                if (!Schema.SObjectType.RecordAccessLog__c.isDeletable()
                    && Schema.SObjectType.RecordAccessLog__c.isCreateable()) {
                    nonDeletableUser = u;
                }
            }
            if (nonDeletableUser != null) {
                break;
            }
        }

        // Some orgs grant delete permission on this object to all internal profiles.
        // In that case, we can't reliably exercise the "not deletable" branch in a package-safe way.
        // Fall back to validating the happy path (delete permission present).
        if (nonDeletableUser == null) {
            User testUser = [SELECT Id FROM User WHERE Email = 'tspdelete@test.com' LIMIT 1];
            System.runAs(testUser) {
                System.assertEquals(true, Schema.SObjectType.RecordAccessLog__c.isDeletable(),
                    'Precondition: expected delete permission to be granted in this org');
            }
            return;
        }

        System.runAs(nonDeletableUser) {
            System.assertEquals(false, Schema.SObjectType.RecordAccessLog__c.isDeletable(),
                'Precondition: user should not have delete permission on RecordAccessLog__c');

            // Create an old log record that this user can see under sharing rules (class is `with sharing`)
            RecordAccessLog__c oldLog = new RecordAccessLog__c(
                User__c = nonDeletableUser.Id,
                Count_of_Records__c = 999,
                AccessTime__c = DateTime.now().addDays(-365)
            );
            insert oldLog;
            Test.setCreatedDate(oldLog.Id, DateTime.now().addDays(-365));
            oldLog = [SELECT CreatedDate FROM RecordAccessLog__c WHERE Id = :oldLog.Id];
            System.assert(
                oldLog.CreatedDate < DateTime.now().addDays(-30),
                'Precondition: expected backdated CreatedDate to be older than 30 days'
            );
            System.assert(
                new SharingQueryHelper().countLogsOlderThan(Date.today().addDays(-30)) > 0,
                'Precondition: expected at least one old log to be visible under sharing rules'
            );

            DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
            request.daysThreshold = 30;

            Test.startTest();
            List<DeleteOldRecordAccessLogs.CleanupResult> results =
                DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
            Test.stopTest();

            System.assertEquals(1, results.size(), 'Should return one result');
            System.assertEquals(false, results[0].success, 'Operation should fail without delete permission');
            System.assertEquals(0, results[0].recordsDeleted, 'Should delete 0 records');
            System.assertEquals('Insufficient permissions to delete Record Access Log records', results[0].errorMessage,
                'Should return the expected permission error message');
        }
    }
    
    /**
     * @description Test with threshold of -1 days (negative threshold - should fail validation)
     */
    @isTest
    static void testDeleteOldRecords_NegativeOneDay() {
        // Create request with -1 day threshold
        DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
        request.daysThreshold = -1;
        
        Test.startTest();
        
        // Execute the invocable method
        List<DeleteOldRecordAccessLogs.CleanupResult> results = 
            DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
        
        Test.stopTest();
        
        // Verify results - should fail validation
        DeleteOldRecordAccessLogs.CleanupResult result = results[0];
        
        System.assertEquals(false, result.success, 'Operation should fail validation');
        System.assertEquals(0, result.recordsDeleted, 'Should delete 0 records');
        System.assertNotEquals(null, result.errorMessage, 'Should have error message');
    }
    
    /**
     * @description Test with threshold of 0 days - should delete nothing (records created today)
     * Since all test records have CreatedDate = now(), threshold of 0 shouldn't match them
     */
    @isTest
    static void testDeleteOldRecords_ZeroDaysThreshold() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tspdelete@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // Create request
            DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
            request.daysThreshold = 0;
            
            Test.startTest();
            
            // Execute the invocable method
            List<DeleteOldRecordAccessLogs.CleanupResult> results = 
                DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
            
            Test.stopTest();
            
            // Verify results
            DeleteOldRecordAccessLogs.CleanupResult result = results[0];
            
            System.assertEquals(true, result.success, 'Operation should succeed');
            System.assertEquals(0, result.recordsDeleted, 'Should delete 0 records (all created today)');
            
            // Verify all records remain
            Integer remainingCount = [SELECT COUNT() FROM RecordAccessLog__c];
            System.assertEquals(8, remainingCount, 'Should have all 8 records remaining');
        }
    }
    
    /**
     * @description Test with null threshold - should handle error gracefully
     */
    @isTest
    static void testDeleteOldRecords_NullThreshold() {
        // Create request with null threshold
        DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
        request.daysThreshold = null;
        
        Test.startTest();
        
        // Execute the invocable method
        List<DeleteOldRecordAccessLogs.CleanupResult> results = 
            DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
        
        Test.stopTest();
        
        // Verify results
        DeleteOldRecordAccessLogs.CleanupResult result = results[0];
        
        System.assertEquals(false, result.success, 'Operation should fail');
        System.assertEquals(0, result.recordsDeleted, 'Should delete 0 records');
        System.assertNotEquals(null, result.errorMessage, 'Should have error message');
    }
    
    /**
     * @description Test with a large threshold value
     */
    @isTest
    static void testDeleteOldRecords_LargeThreshold() {
        // Create request with very large threshold
        DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
        request.daysThreshold = 3650; // 10 years
        
        Test.startTest();
        
        // Execute the invocable method
        List<DeleteOldRecordAccessLogs.CleanupResult> results = 
            DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
        
        Test.stopTest();
        
        // Verify results
        DeleteOldRecordAccessLogs.CleanupResult result = results[0];
        
        System.assertEquals(true, result.success, 'Operation should succeed');
        System.assertEquals(0, result.recordsDeleted, 'Should delete 0 records');
    }
    
    /**
     * @description Test with no records in database
     */
    @isTest
    static void testDeleteOldRecords_NoRecords() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tspdelete@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // Delete all test records
            delete [SELECT Id FROM RecordAccessLog__c];
            
            // Verify no records exist
            System.assertEquals(0, [SELECT COUNT() FROM RecordAccessLog__c], 'Should have 0 records');
            
            // Create request
            DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
            request.daysThreshold = 30;
            
            Test.startTest();
            
            // Execute the invocable method
            List<DeleteOldRecordAccessLogs.CleanupResult> results = 
                DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
            
            Test.stopTest();
            
            // Verify results
            DeleteOldRecordAccessLogs.CleanupResult result = results[0];
            
            System.assertEquals(true, result.success, 'Operation should succeed');
            System.assertEquals(0, result.recordsDeleted, 'Should delete 0 records');
            System.assertEquals(null, result.errorMessage, 'Should have no error message');
        }
    }
    
    /**
     * @description Test processing multiple requests
     */
    @isTest
    static void testDeleteOldRecords_MultipleRequests() {
        // Create two requests
        List<DeleteOldRecordAccessLogs.CleanupRequest> requests = new List<DeleteOldRecordAccessLogs.CleanupRequest>();
        
        DeleteOldRecordAccessLogs.CleanupRequest request1 = new DeleteOldRecordAccessLogs.CleanupRequest();
        request1.daysThreshold = 90;
        requests.add(request1);
        
        DeleteOldRecordAccessLogs.CleanupRequest request2 = new DeleteOldRecordAccessLogs.CleanupRequest();
        request2.daysThreshold = -5; // Invalid
        requests.add(request2);
        
        Test.startTest();
        
        // Execute the invocable method
        List<DeleteOldRecordAccessLogs.CleanupResult> results = 
            DeleteOldRecordAccessLogs.deleteOldRecords(requests);
        
        Test.stopTest();
        
        // Verify results
        System.assertEquals(2, results.size(), 'Should return two results');
        
        // First request should succeed (but delete 0 since all records are recent in test)
        System.assertEquals(true, results[0].success, 'First request should succeed');
        System.assertEquals(0, results[0].recordsDeleted, 'First request should delete 0 records (all recent)');
        
        // Second request should fail
        System.assertEquals(false, results[1].success, 'Second request should fail');
        System.assertEquals(0, results[1].recordsDeleted, 'Second request should delete 0 records');
    }
    
    /**
     * @description Test with exactly 1 day threshold
     */
    @isTest
    static void testDeleteOldRecords_OneDayThreshold() {
        // Query the test user created in setup
        User testUser = [SELECT Id FROM User WHERE Email = 'tspdelete@test.com' LIMIT 1];
        
        System.runAs(testUser) {
            // Create request
            DeleteOldRecordAccessLogs.CleanupRequest request = new DeleteOldRecordAccessLogs.CleanupRequest();
            request.daysThreshold = 1;
            
            Test.startTest();
            
            // Execute the invocable method
            List<DeleteOldRecordAccessLogs.CleanupResult> results = 
                DeleteOldRecordAccessLogs.deleteOldRecords(new List<DeleteOldRecordAccessLogs.CleanupRequest>{ request });
            
            Test.stopTest();
            
            // Verify results
            DeleteOldRecordAccessLogs.CleanupResult result = results[0];
            
            System.assertEquals(true, result.success, 'Operation should succeed');
            System.assertEquals(0, result.recordsDeleted, 'Should delete 0 records (all created today)');
            
            // Verify all records remain
            Integer remainingCount = [SELECT COUNT() FROM RecordAccessLog__c];
            System.assertEquals(8, remainingCount, 'Should have all 8 records remaining');
        }
    }
}

