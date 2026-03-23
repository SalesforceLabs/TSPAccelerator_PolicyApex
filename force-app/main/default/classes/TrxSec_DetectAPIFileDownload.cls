/**
 * @description Transaction Security Policy condition to detect file downloads via API
 */
global with sharing class TrxSec_DetectAPIFileDownload implements TxnSecurity.EventCondition {
    /***********************************************************
    * DETECT FILE DOWNLOADS VIA API.
    * FileEventStore is triggered when files are downloaded via API (FileAction = API_DOWNLOAD).
    * This policy detects when any file is downloaded through the API, which can be 
    * monitored for security and compliance purposes.
    ***********************************************************/

    global boolean evaluate(SObject event){
        switch on event {
            when FileEventStore fileEventStore {
                return evaluate(fileEventStore);
            }
            when null {
                // Don't take policy action when event is null
                return false;
            }
            when else {
                // Don't take policy action when event is not handled
                return false;
            }
        }
    }
    
    @TestVisible
    private Boolean evaluate(FileEventStore fileEventStore) {
        // Detect API_DOWNLOAD actions
        if (String.isBlank(fileEventStore.FileAction)) {
            return false;
        }
        
        return fileEventStore.FileAction == 'API_DOWNLOAD';
    }
}
