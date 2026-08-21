/**
 * @description Test class for TrxSec_DetectAPIFileDownload
 */
@isTest
private class TrxSec_DetectAPIFileDownloadTest {

    @isTest
    static void testDetectsAPIDownload() {
        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = 'API_DOWNLOAD';

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(true, result, 'Should detect API_DOWNLOAD file action');
    }

    @isTest
    static void testReturnsFalseWhenFileActionIsNotAPIDownload() {
        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = 'UI_DOWNLOAD';

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(false, result, 'Should not trigger for non-API downloads');
    }

    @isTest
    static void testReturnsFalseWhenFileActionIsNull() {
        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = null;

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(false, result, 'Should handle null FileAction');
    }

    @isTest
    static void testReturnsFalseWhenFileActionIsBlank() {
        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = '';

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(false, result, 'Should handle blank FileAction');
    }

    @isTest
    static void testDoesNotDetectUIPreview() {
        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = 'UI_PREVIEW';

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(false, result, 'Should not trigger for UI_PREVIEW');
    }

    @isTest
    static void testDoesNotDetectUIUpload() {
        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = 'UI_UPLOAD';

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(false, result, 'Should not trigger for UI_UPLOAD');
    }

    @isTest
    static void testDoesNotDetectAPIUpload() {
        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = 'API_UPLOAD';

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(false, result, 'Should not trigger for API_UPLOAD');
    }
    
    @isTest
    static void testHandlesNullEvent() {
        TrxSec_DetectAPIFileDownload policy = new TrxSec_DetectAPIFileDownload();
        Boolean result = policy.evaluate((SObject)null);
        System.assertEquals(false, result, 'Should handle null event');
    }
    
    @isTest
    static void testHandlesWrongEventType() {
        // Test with a different event type to cover the 'when else' branch
        ApiEvent apiEvent = new ApiEvent();
        TrxSec_DetectAPIFileDownload policy = new TrxSec_DetectAPIFileDownload();
        Boolean result = policy.evaluate(apiEvent);
        System.assertEquals(false, result, 'Should return false for wrong event type');
    }

    @isTest
    static void testExcludedUserDoesNotTrip() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = userId,
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_API_FILE_DOWNLOAD
            )
        };

        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = 'API_DOWNLOAD';
        testEvent.UserId = userId;

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(
            false,
            result,
            'An excluded user must not trip even for API_DOWNLOAD'
        );
    }

    @isTest
    static void testExclusionForOtherUserDoesNotSkipCurrentUser() {
        Id userId = UserInfo.getUserId();
        Profile p = [SELECT Id FROM Profile WHERE Name='Standard User' LIMIT 1];
        User otherUser = new User(
            Alias = 'exoth',
            Email = 'exclusion.file.other@testorg.com',
            EmailEncodingKey = 'UTF-8',
            LastName = 'ExclusionOther',
            LanguageLocaleKey = 'en_US',
            LocaleSidKey = 'en_US',
            ProfileId = p.Id,
            TimeZoneSidKey = 'America/Los_Angeles',
            UserName = 'exclusion.file.other' + Datetime.now().getTime() + '@testorg.com'
        );
        insert otherUser;

        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            new Policy_Exclusion__mdt(
                User_ID__c = otherUser.Id,
                Policy_Apex__c = TrxSec_PolicyExclusions.POLICY_API_FILE_DOWNLOAD
            )
        };

        FileEventStore testEvent = new FileEventStore();
        testEvent.FileAction = 'API_DOWNLOAD';
        testEvent.UserId = userId;

        Boolean result = new TrxSec_DetectAPIFileDownload().evaluate(testEvent);
        System.assertEquals(
            true,
            result,
            'API_DOWNLOAD must still trip when a different user is the one excluded'
        );
    }
}
