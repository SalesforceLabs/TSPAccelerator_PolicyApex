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
}
