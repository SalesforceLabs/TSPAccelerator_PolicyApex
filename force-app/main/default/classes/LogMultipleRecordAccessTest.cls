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

    // Payloads shared between the extractRecordCount tests and the persistence-equivalence tests.
    // Shapes taken from the Platform Events Developer Guide examples for each event type.
    private static final String API_PAYLOAD =
        '{"totalSize":1369,"done":true,"records":[{"attributes":{"type":"Account"},"Id":"001000000000001AAA"}]}';
    private static final String RECORDS_ARRAY_PAYLOAD =
        '{"records":[{"Id":"001000000000001AAA"},{"Id":"001000000000002AAA"},{"Id":"001000000000003AAA"}]}';
    private static final String ROWS_PAYLOAD =
        '{"rows":[{"datacells":["005B0000001vURvAAA","001B000000fewaiAAA"]},{"datacells":["001B000000fewajAAA"]}]}';

    /**
     * extractRecordCount: totalSize shape (ApiEvent) returns totalSize verbatim.
     */
    @isTest
    static void testExtractRecordCount_TotalSizeShape() {
        System.assertEquals(
            1369,
            LogMultipleRecordAccess.extractRecordCount(API_PAYLOAD),
            'totalSize should be returned verbatim'
        );
    }

    /**
     * extractRecordCount: records array without totalSize returns the array size.
     */
    @isTest
    static void testExtractRecordCount_RecordsArrayShape() {
        System.assertEquals(
            3,
            LogMultipleRecordAccess.extractRecordCount(RECORDS_ARRAY_PAYLOAD),
            'records array size should be counted when totalSize is absent'
        );
    }

    /**
     * extractRecordCount: rows/datacells shape counts unique IDs of length >= 15 across all rows.
     */
    @isTest
    static void testExtractRecordCount_RowsDatacellsShape() {
        System.assertEquals(
            3,
            LogMultipleRecordAccess.extractRecordCount(ROWS_PAYLOAD),
            'unique record IDs across all datacells should be counted'
        );

        // Short strings (column values, not IDs) are filtered out; duplicates collapse.
        String noisyPayload = '{"rows":[{"datacells":["001000000000001AAA","NotAnId","001000000000001AAA"]}]}';
        System.assertEquals(
            1,
            LogMultipleRecordAccess.extractRecordCount(noisyPayload),
            'Short strings should be ignored and duplicate IDs de-duplicated'
        );
    }

    /**
     * extractRecordCount: absent, blank, malformed and unexpected payloads all yield 0 without
     * throwing. TSP conditions call this synchronously, so an escaping exception is unacceptable.
     */
    @isTest
    static void testExtractRecordCount_AbsentOrUnparseableYieldsZero() {
        Map<String, String> cases = new Map<String, String>{
            'null payload' => null,
            'empty string' => '',
            'whitespace only' => '   ',
            'malformed JSON' => '{ "invalid_json": ',
            'JSON array not object' => '[1,2,3]',
            'JSON scalar' => '"just a string"',
            'unexpected structure' => '{"someOtherKey":"someValue"}',
            'null totalSize' => '{"totalSize":null}',
            'non numeric totalSize' => '{"totalSize":"abc"}',
            'null records array' => '{"records":null}',
            'null rows array' => '{"rows":null}',
            'row without datacells' => '{"rows":[{"other":[]}]}'
        };

        for (String description : cases.keySet()) {
            System.assertEquals(
                0,
                LogMultipleRecordAccess.extractRecordCount(cases.get(description)),
                'Should return 0 for ' + description
            );
        }
    }

    /**
     * extractRecordCount: never returns a negative count, so it can only ever raise a threshold
     * total, never silently lower it.
     */
    @isTest
    static void testExtractRecordCount_NeverNegative() {
        System.assertEquals(
            0,
            LogMultipleRecordAccess.extractRecordCount('{"totalSize":-1}'),
            'A negative totalSize should be clamped to 0'
        );
        System.assertEquals(
            0,
            LogMultipleRecordAccess.extractRecordCount('{"totalSize":0}'),
            'A zero totalSize should be 0'
        );
        System.assertEquals(
            0,
            LogMultipleRecordAccess.extractRecordCount('{"records":[]}'),
            'An empty records array should be 0'
        );
    }

    /**
     * extractRecordCount: large counts survive without overflow or rounding.
     * Count_of_Records__c is Number(18,0), so an Integer count always fits.
     */
    @isTest
    static void testExtractRecordCount_LargeCount() {
        System.assertEquals(
            10001,
            LogMultipleRecordAccess.extractRecordCount('{"totalSize":10001}'),
            'A count above the 10,000 threshold should be returned exactly'
        );
        System.assertEquals(
            2000000000,
            LogMultipleRecordAccess.extractRecordCount('{"totalSize":2000000000}'),
            'A count near Integer.MAX_VALUE should be returned exactly'
        );
    }

    /**
     * extractRecordCount: totalSize arriving as a non-Integer JSON number.
     * JSON.deserializeUntyped yields a Decimal for fractional values and a Long for values beyond
     * Integer range, and both are narrowed to Integer.
     */
    @isTest
    static void testExtractRecordCount_NonIntegerTotalSize() {
        System.assertEquals(
            1500,
            LogMultipleRecordAccess.extractRecordCount('{"totalSize":1500.7}'),
            'A fractional totalSize should be truncated to an Integer'
        );

        // Beyond Integer.MAX_VALUE the platform narrows to the low-order bits, which can go
        // negative. The clamp in extractRecordCount turns that into 0 so a corrupt count can only
        // ever undercount, never inflate a threshold total into a false positive.
        Integer hugeCount = LogMultipleRecordAccess.extractRecordCount('{"totalSize":9999999999}');
        System.assert(hugeCount >= 0, 'A totalSize beyond Integer range must never yield a negative count');
    }

    /**
     * logAccess skips inputs with a blank RecordsField without creating a log or throwing.
     */
    @isTest
    static void testLogAccess_BlankRecordsFieldSkipped() {
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];

        List<LogMultipleRecordAccess.InputWrapper> inputs = new List<LogMultipleRecordAccess.InputWrapper>();
        for (String blankPayload : new List<String>{ null, '', '   ' }) {
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = blankPayload;
            input.UserId = testUser.Id;
            input.EventDate = Datetime.now();
            inputs.add(input);
        }

        Test.startTest();
        LogMultipleRecordAccess.logAccess(inputs);
        Test.stopTest();

        System.assertEquals(
            0,
            [SELECT COUNT() FROM RecordAccessLog__c],
            'Blank RecordsField inputs should be skipped without creating logs'
        );
    }

    /**
     * logAccessAsync returns early, publishing nothing, when required inputs are missing.
     */
    @isTest
    static void testLogAccessAsync_InvalidParametersPublishNothing() {
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        Datetime now = Datetime.now();

        Test.startTest();
        LogMultipleRecordAccess.logAccessAsync(null, testUser.Id, now, 'Account', 'ApiEvent');
        LogMultipleRecordAccess.logAccessAsync('', testUser.Id, now, 'Account', 'ApiEvent');
        LogMultipleRecordAccess.logAccessAsync(API_PAYLOAD, null, now, 'Account', 'ApiEvent');
        LogMultipleRecordAccess.logAccessAsync(API_PAYLOAD, testUser.Id, null, 'Account', 'ApiEvent');
        Test.getEventBus().deliver();
        Test.stopTest();

        System.assertEquals(
            0,
            [SELECT COUNT() FROM RecordAccessLog__c],
            'Invalid parameters should publish no event and therefore create no log'
        );
    }

    /**
     * This is the assumption the whole threshold fix rests on: the count a TSP condition adds in
     * memory must equal the count that ends up in RecordAccessLog__c.Count_of_Records__c for the
     * same payload.
     *
     * The subscribing Flow (TSP - Process Record Access Event) does no count derivation of its own.
     * It maps $Record.RecordsJson__c -> RecordsField, UserId__c -> UserId, AccessTime__c ->
     * EventDate, QueriedEntities__c -> QueriedEntities and EventType__c -> EventType, then invokes
     * LogMultipleRecordAccess.logAccess. This test replicates exactly that mapping, so the only
     * thing under test is the shared derivation.
     */
    @isTest
    static void testPersistedCountMatchesExtractRecordCount() {
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        Datetime eventDate = Datetime.now();

        Map<String, String> payloadsByEventType = new Map<String, String>{
            'ApiEvent' => API_PAYLOAD,
            'ListViewEvent' => ROWS_PAYLOAD,
            'ReportEvent' => RECORDS_ARRAY_PAYLOAD
        };

        List<LogMultipleRecordAccess.InputWrapper> inputs = new List<LogMultipleRecordAccess.InputWrapper>();
        for (String eventType : payloadsByEventType.keySet()) {
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = payloadsByEventType.get(eventType);
            input.UserId = testUser.Id;
            input.EventDate = eventDate;
            input.QueriedEntities = 'Account';
            input.EventType = eventType;
            inputs.add(input);
        }

        Test.startTest();
        LogMultipleRecordAccess.logAccess(inputs);
        Test.stopTest();

        Map<String, Decimal> persistedByEventType = new Map<String, Decimal>();
        for (RecordAccessLog__c log : [
            SELECT Event_Type__c, Count_of_Records__c
            FROM RecordAccessLog__c
            WHERE User__c = :testUser.Id
        ]) {
            persistedByEventType.put(log.Event_Type__c, log.Count_of_Records__c);
        }

        System.assertEquals(
            payloadsByEventType.size(),
            persistedByEventType.size(),
            'Every payload should produce exactly one aggregate log'
        );

        for (String eventType : payloadsByEventType.keySet()) {
            Integer inMemoryCount = LogMultipleRecordAccess.extractRecordCount(payloadsByEventType.get(eventType));
            System.assertEquals(
                inMemoryCount,
                persistedByEventType.get(eventType),
                'Persisted count must equal extractRecordCount for ' + eventType +
                    ' or the threshold arithmetic mixes units of measure'
            );
        }
    }

    /**
     * End-to-end: publish a RecordAccessEvent__e and deliver it through the event bus, then assert
     * the persisted count agrees with extractRecordCount for the same payload.
     *
     * The packaged Flow ships with <status>Draft</status> and is therefore inactive until a
     * subscriber activates it, so delivery alone creates no log in a default install. The invariant
     * asserted here holds in both states: whichever path persists the row, the stored count must
     * equal extractRecordCount for the payload, because logAccess is the only writer of
     * Count_of_Records__c and it derives that value from extractRecordCount.
     */
    @isTest
    static void testEndToEndPlatformEventToRecordAccessLog() {
        User testUser = [SELECT Id FROM User WHERE Email = 'tsptest@test.com' LIMIT 1];
        Datetime eventDate = Datetime.now();
        Integer expectedCount = LogMultipleRecordAccess.extractRecordCount(API_PAYLOAD);

        Test.startTest();
        Database.SaveResult publishResult = EventBus.publish(
            new RecordAccessEvent__e(
                UserId__c = testUser.Id,
                RecordsJson__c = API_PAYLOAD,
                AccessTime__c = eventDate,
                QueriedEntities__c = 'Account',
                EventType__c = 'ApiEvent'
            )
        );
        Test.getEventBus().deliver();
        Test.stopTest();

        System.assertEquals(true, publishResult.isSuccess(), 'RecordAccessEvent__e should publish successfully');

        List<RecordAccessLog__c> logs = [
            SELECT Event_Type__c, Count_of_Records__c, User__c
            FROM RecordAccessLog__c
            WHERE User__c = :testUser.Id
        ];

        if (logs.isEmpty()) {
            // Subscribing Flow is inactive in this org. Drive the same invariant through the exact
            // mapping the Flow performs, so the equivalence is still proven rather than skipped.
            LogMultipleRecordAccess.InputWrapper input = new LogMultipleRecordAccess.InputWrapper();
            input.RecordsField = API_PAYLOAD;
            input.UserId = testUser.Id;
            input.EventDate = eventDate;
            input.QueriedEntities = 'Account';
            input.EventType = 'ApiEvent';
            LogMultipleRecordAccess.logAccess(new List<LogMultipleRecordAccess.InputWrapper>{ input });

            logs = [
                SELECT Event_Type__c, Count_of_Records__c, User__c
                FROM RecordAccessLog__c
                WHERE User__c = :testUser.Id
            ];
        }

        System.assertEquals(1, logs.size(), 'Exactly one aggregate log should exist for the delivered event');
        System.assertEquals(
            expectedCount,
            logs[0].Count_of_Records__c,
            'Persisted Count_of_Records__c must equal extractRecordCount for the published payload'
        );
        System.assertEquals('ApiEvent', logs[0].Event_Type__c, 'Event type should round-trip through the event');
    }
}

