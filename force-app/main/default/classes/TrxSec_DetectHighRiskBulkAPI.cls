/**
 * @description Transaction Security Policy condition to detect Bulk API operations based on high-risk fields
 */
global with sharing class TrxSec_DetectHighRiskBulkAPI implements TxnSecurity.EventCondition {
    /***********************************************************
    * DETECT BULK API OPERATIONS WITH A FIELD CLASSIFIED AS HIGH-RISK.
    ***********************************************************/

    private static final Integer NO_SCOPE = -1;
    private static final String SELECT_KEYWORD = 'select';
    private static final String FROM_KEYWORD = 'from';
    private static final String OPEN_PAREN = '(';
    private static final String CLOSE_PAREN = ')';
    private static final String QUOTE = '\'';
    private static final String BACKSLASH = '\\';
    private static final String IDENTIFIER_PATTERN = '[a-zA-Z][a-zA-Z0-9_]*';

    private static final Map<String, Map<String, Schema.SObjectType>> childTypesByParent =
        new Map<String, Map<String, Schema.SObjectType>>();

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
        
        return hasConfidentialFieldsInQuery(bulkEvent.Query, highRiskLevels);
    }
    
    private boolean hasConfidentialFieldsInQuery(String query, List<String> highRiskLevels){
        // Each entity's fields are matched against the whole query rather than against the clause
        // that entity came from, so a shared field name across entities errs toward detection
        for (String entity : extractEntitiesFromQuery(query)) {
            for (String confidentialField : provider.getConfidentialFields(entity, highRiskLevels)) {
                if (query.containsIgnoreCase(confidentialField)) {
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * @description Every entity a query reads: the top-level FROM plus the FROM of each
     * subquery, deduplicated case-insensitively.
     */
    @TestVisible
    private static List<String> extractEntitiesFromQuery(String query) {
        if (String.isBlank(query)) {
            return new List<String>();
        }

        List<QueryScope> scopes = parseScopes(query);
        Map<String, String> entitiesByKey = new Map<String, String>();
        for (Integer i = 0; i < scopes.size(); i++) {
            String entity = resolveEntity(scopes, i);
            if (String.isNotBlank(entity)) {
                entitiesByKey.put(entity.toLowerCase(), entity);
            }
        }
        return entitiesByKey.values();
    }

    /**
     * @description One scope per SELECT in the query, the outermost first. A scope is appended
     * when its subquery opens, so a scope's parent always precedes it in the list.
     */
    private static List<QueryScope> parseScopes(String query) {
        List<String> tokens = tokenize(query);
        List<QueryScope> scopes = new List<QueryScope>{ new QueryScope(NO_SCOPE, false) };
        // Tracks which open parenthesis started a subquery so the closing one restores its parent
        List<Integer> openParens = new List<Integer>();
        Integer current = 0;

        for (Integer i = 0; i < tokens.size(); i++) {
            String token = tokens[i];
            if (token == OPEN_PAREN) {
                if (i + 1 < tokens.size() && SELECT_KEYWORD.equalsIgnoreCase(tokens[i + 1])) {
                    // A subquery reached before its parent's FROM sits in the SELECT list, so it
                    // targets a child relationship name rather than an entity name.
                    scopes.add(new QueryScope(current, scopes[current].target == null));
                    current = scopes.size() - 1;
                    openParens.add(current);
                } else {
                    openParens.add(NO_SCOPE);
                }
            } else if (token == CLOSE_PAREN) {
                if (!openParens.isEmpty()) {
                    Integer closed = openParens.remove(openParens.size() - 1);
                    if (closed != NO_SCOPE) {
                        current = scopes[closed].parentScope;
                    }
                }
            } else if (scopes[current].target == null
                && FROM_KEYWORD.equalsIgnoreCase(token)
                && i + 1 < tokens.size()
                && Pattern.matches(IDENTIFIER_PATTERN, tokens[i + 1])) {
                scopes[current].target = tokens[i + 1];
            }
        }
        return scopes;
    }

    private static String resolveEntity(List<QueryScope> scopes, Integer index) {
        QueryScope scope = scopes[index];
        if (String.isBlank(scope.target)) {
            return null;
        }
        if (!scope.targetsRelationship) {
            return scope.target;
        }

        String parentEntity = scope.parentScope == NO_SCOPE
            ? null
            : resolveEntity(scopes, scope.parentScope);
        if (String.isBlank(parentEntity)) {
            // Without a parent to resolve against, treat the target as an entity so that a query
            // this parser cannot make sense of still gets classified against something
            return scope.target;
        }
        return childEntity(parentEntity, scope.target);
    }

    private static String childEntity(String parentEntity, String relationshipName) {
        Schema.SObjectType childType = childTypesByRelationship(parentEntity).get(relationshipName.toLowerCase());
        return childType == null
            ? null
            : childType.getDescribe(Schema.SObjectDescribeOptions.DEFERRED).getName();
    }

    private static Map<String, Schema.SObjectType> childTypesByRelationship(String parentEntity) {
        String parentKey = parentEntity.toLowerCase();
        if (!childTypesByParent.containsKey(parentKey)) {
            childTypesByParent.put(parentKey, describeChildTypes(parentEntity));
        }
        return childTypesByParent.get(parentKey);
    }

    private static Map<String, Schema.SObjectType> describeChildTypes(String parentEntity) {
        Map<String, Schema.SObjectType> childTypes = new Map<String, Schema.SObjectType>();

        List<Schema.DescribeSObjectResult> describes;
        try {
            describes = Schema.describeSObjects(new List<String>{ parentEntity });
        } catch (Exception parentNotAnEntity) {
            // The parent name comes from parsed query text, so it may not name an entity at all
            return childTypes;
        }
        if (describes.isEmpty()) {
            return childTypes;
        }

        for (Schema.ChildRelationship childRelationship : describes[0].getChildRelationships()) {
            String relationshipName = childRelationship.getRelationshipName();
            if (String.isNotBlank(relationshipName)) {
                childTypes.put(relationshipName.toLowerCase(), childRelationship.getChildSObject());
            }
        }
        return childTypes;
    }

    /**
     * @description Splits the query into identifiers and parentheses. String literals are
     * dropped so a quoted "from" cannot be mistaken for the keyword.
     */
    private static List<String> tokenize(String query) {
        List<String> tokens = new List<String>();
        Integer length = query.length();
        Integer i = 0;

        while (i < length) {
            String character = query.substring(i, i + 1);
            if (character == QUOTE) {
                i = endOfLiteral(query, i);
            } else if (character == OPEN_PAREN || character == CLOSE_PAREN) {
                tokens.add(character);
                i++;
            } else if (isSeparator(character)) {
                i++;
            } else {
                Integer start = i;
                i++;
                while (i < length && !isTokenBoundary(query.substring(i, i + 1))) {
                    i++;
                }
                tokens.add(query.substring(start, i));
            }
        }
        return tokens;
    }

    private static Integer endOfLiteral(String query, Integer quoteIndex) {
        Integer length = query.length();
        Integer i = quoteIndex + 1;
        while (i < length) {
            String character = query.substring(i, i + 1);
            i++;
            if (character == BACKSLASH) {
                i++;
            } else if (character == QUOTE) {
                break;
            }
        }
        return i;
    }

    private static Boolean isTokenBoundary(String character) {
        return character == OPEN_PAREN
            || character == CLOSE_PAREN
            || character == QUOTE
            || isSeparator(character);
    }

    private static Boolean isSeparator(String character) {
        return character == ',' || String.isBlank(character);
    }

    private class QueryScope {
        private final Integer parentScope;
        private final Boolean targetsRelationship;
        private String target;

        private QueryScope(Integer parentScope, Boolean targetsRelationship) {
            this.parentScope = parentScope;
            this.targetsRelationship = targetsRelationship;
        }
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
