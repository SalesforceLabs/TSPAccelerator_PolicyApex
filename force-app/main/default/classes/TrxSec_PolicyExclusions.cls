/**
 * @description Resolves subscriber-configured per-user exclusions for packaged TSP
 * conditions. Backed by Policy_Exclusion__mdt: each record names a User ID and the
 * Apex class of the policy it applies to. getAll() on a custom metadata type is free of SOQL, which
 * matters because this is invoked from a metered TxnSecurity.EventCondition.
 *
 * Package-internal on purpose: isExcluded is a bypass of policy enforcement for a
 * named user, so it is public (visible only inside trxsecurity) rather than global.
 * Subscribers configure exclusions by creating Policy_Exclusion__mdt records, not
 * by calling this class.
 *
 * Custom metadata records cannot be created via DML, so tests inject synthetic
 * records through overridesForTest. A null list means "read getAll()"; an empty
 * list means "no exclusions" and isolates a test from any org records.
 */
public with sharing class TrxSec_PolicyExclusions {

    public static final String POLICY_TOTAL_ACCESS_API = 'TrxSec_DetectTotalAccessAPI';
    public static final String POLICY_TOTAL_ACCESS_LIST_VIEW = 'TrxSec_DetectTotalAccessListView';
    public static final String POLICY_TOTAL_ACCESS_REPORT_EXPORT = 'TrxSec_DetectTotalAccessReportExport';
    public static final String POLICY_LOGIN_AS = 'TrxSec_DetectLoginAsEvent';
    public static final String POLICY_IMPOSSIBLE_TRAVEL = 'TrxSec_DetectImpossibleTravel';
    public static final String POLICY_API_FILE_DOWNLOAD = 'TrxSec_DetectAPIFileDownload';

    // Normalized policy key -> 18-character user Ids. Built once per transaction.
    private static Map<String, Set<String>> exclusionsByPolicy;

    /**
     * When non-null, used instead of Policy_Exclusion__mdt.getAll() so tests can
     * drive the same parse/normalize path the production lookup uses.
     */
    @TestVisible
    private static List<Policy_Exclusion__mdt> overridesForTest;

    /**
     * @description Returns true when a Policy_Exclusion__mdt record names this user
     * for the given policy key. Returns false when policyKey is
     * blank, userId is null, no matching record exists, or anything throws: an
     * exception escaping a TSP condition has unpredictable enforcement consequences,
     * and "not excluded" leaves the policy enforcing.
     *
     * @param policyKey One of the POLICY_* constants (the policy's Apex class name).
     * @param userId The event's UserId, not UserInfo.getUserId().
     */
    public static Boolean isExcluded(String policyKey, Id userId) {
        if (String.isBlank(policyKey) || userId == null) {
            return false;
        }

        try {
            Map<String, Set<String>> byPolicy = getExclusionsByPolicy();
            String normalizedUserId = normalizeUserId(String.valueOf(userId));
            if (normalizedUserId == null) {
                return false;
            }
            return containsUser(byPolicy.get(normalizePolicyKey(policyKey)), normalizedUserId);
        } catch (Exception ex) {
            System.debug(
                LoggingLevel.WARN,
                'TrxSec_PolicyExclusions.isExcluded: treating as not excluded due to ' +
                    ex.getTypeName()
            );
            return false;
        }
    }

    private static Map<String, Set<String>> getExclusionsByPolicy() {
        if (exclusionsByPolicy != null) {
            return exclusionsByPolicy;
        }

        exclusionsByPolicy = new Map<String, Set<String>>();
        List<Policy_Exclusion__mdt> records = overridesForTest != null
            ? overridesForTest
            : Policy_Exclusion__mdt.getAll().values();

        for (Policy_Exclusion__mdt setting : records) {
            indexRecord(setting);
        }
        return exclusionsByPolicy;
    }

    /**
     * Indexes one CMT row into the cache. Blank user, blank policy, or a value that
     * is not a Salesforce Id are skipped so a single bad record cannot poison the
     * whole lookup. Policy_Apex__c is treated as a comma-separated list so one
     * record can cover several policies for the same user.
     */
    private static void indexRecord(Policy_Exclusion__mdt setting) {
        if (setting == null || String.isBlank(setting.User_ID__c) || String.isBlank(setting.Policy_Apex__c)) {
            return;
        }

        String normalizedUserId = normalizeUserId(setting.User_ID__c);
        if (normalizedUserId == null) {
            return;
        }

        for (String token : setting.Policy_Apex__c.split(',')) {
            String key = normalizePolicyKey(token);
            if (String.isBlank(key)) {
                continue;
            }
            if (!exclusionsByPolicy.containsKey(key)) {
                exclusionsByPolicy.put(key, new Set<String>());
            }
            exclusionsByPolicy.get(key).add(normalizedUserId);
        }
    }

    private static Boolean containsUser(Set<String> userIds, String normalizedUserId) {
        return userIds != null && userIds.contains(normalizedUserId);
    }

    private static String normalizePolicyKey(String policyKey) {
        return policyKey == null ? null : policyKey.trim().toLowerCase();
    }

    /**
     * Converts a 15- or 18-character Id string to the 18-character form used as the
     * cache key. Returns null when the value is not a Salesforce Id so a typo in
     * Setup cannot throw out of isExcluded.
     */
    private static String normalizeUserId(String rawUserId) {
        try {
            return String.valueOf(Id.valueOf(rawUserId.trim()));
        } catch (Exception ex) {
            return null;
        }
    }
}
