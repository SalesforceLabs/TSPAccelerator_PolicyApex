/**
 * @description Transaction Security Policy condition to detect Bulk API operations based on high-risk fields
 */
global with sharing class TrxSec_DetectHighRiskBulkAPI implements TxnSecurity.EventCondition {
    /***********************************************************
    * DETECT BULK API OPERATIONS WITH A FIELD CLASSIFIED AS HIGH-RISK.
    ***********************************************************/

    public interface Provider {
        List<String> getHighRiskLevels();
        List<String> getConfidentialFields(String entity, List<String> highRiskLevels);
    }

    @TestVisible
    private static Provider provider = new DefaultProvider();

    @TestVisible
    private static void resetProviderForTest() {
        provider = new DefaultProvider();
    }

    global boolean evaluate(SObject event){
        List<String> highRiskLevels = provider.getHighRiskLevels();
        if (highRiskLevels.isEmpty()) { return false; }

        BulkApiResultEventStore bulkEvent = (BulkApiResultEventStore) event;
        
        // Handle null inputs gracefully
        if (String.isBlank(bulkEvent.Query)) {
            return false;
        }
        
        return hasConfidentialFieldsInQuery(bulkEvent.Query.toLowerCase(), highRiskLevels);
    }
    
    private boolean hasConfidentialFieldsInQuery(String query, List<String> highRiskLevels){
        // Extract entity name from query (FROM clause)
        String entity = extractEntityFromQuery(query);
        if (String.isBlank(entity)) {
            return false;
        }
        
        List<String> confidentialFields = provider.getConfidentialFields(entity, highRiskLevels);
        for(String confidentialField : confidentialFields) {
            if (query.containsIgnoreCase(confidentialField)) {
                return true;
            }
        }
        
        return false;
    }
    
    private String extractEntityFromQuery(String query) {
        if (String.isBlank(query)) {
            return null;
        }
        
        // Simple FROM clause extraction for SOQL queries
        // Handles: SELECT ... FROM EntityName or SELECT ... FROM EntityName WHERE ...
        String lowerQuery = query.toLowerCase();
        Integer fromIndex = lowerQuery.indexOf(' from ');
        if (fromIndex == -1) {
            return null;
        }
        
        String afterFrom = query.substring(fromIndex + 6).trim();
        
        // Extract entity name (up to first space, comma, or parenthesis)
        Integer spaceIndex = afterFrom.indexOf(' ');
        Integer commaIndex = afterFrom.indexOf(',');
        Integer parenIndex = afterFrom.indexOf('(');
        
        Integer endIndex = afterFrom.length();
        if (spaceIndex > 0) {
            endIndex = Math.min(endIndex, spaceIndex);
        }
        if (commaIndex > 0) {
            endIndex = Math.min(endIndex, commaIndex);
        }
        if (parenIndex > 0) {
            endIndex = Math.min(endIndex, parenIndex);
        }
        
        return afterFrom.substring(0, endIndex).trim();
    }

    private with sharing class DefaultProvider implements Provider {
        public List<String> getHighRiskLevels() {
            List<FieldSecurityClassification> fieldSecurityClassifications = [
                SELECT ApiName
                FROM FieldSecurityClassification
                WHERE IsHighRiskLevel = TRUE
            ];

            List<String> levels = new List<String>();
            for (FieldSecurityClassification fieldSecurityClassification : fieldSecurityClassifications) {
                levels.add(fieldSecurityClassification.ApiName);
            }
            return levels;
        }

        public List<String> getConfidentialFields(String entity, List<String> highRiskLevels) {
            if (highRiskLevels == null || highRiskLevels.isEmpty()) {
                return new List<String>();
            }

            List<FieldDefinition> fieldDefinitions = [
                SELECT DeveloperName
                FROM FieldDefinition
                WHERE EntityDefinitionId = :entity
                AND SecurityClassification in :highRiskLevels
            ];

            List<String> confidentialFields = new List<String>();
            for (FieldDefinition fieldDefinition : fieldDefinitions) {
                confidentialFields.add(fieldDefinition.DeveloperName.toLowerCase());
            }
            return confidentialFields;
        }
    }
}
