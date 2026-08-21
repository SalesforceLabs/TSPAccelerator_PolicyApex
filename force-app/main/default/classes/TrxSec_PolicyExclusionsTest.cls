/**
 * @description Tests for TrxSec_PolicyExclusions. Custom metadata records cannot be
 * inserted via DML, so tests exercise the parse and match rules through the
 * overridesForTest hook of synthetic Policy_Exclusion__mdt rows.
 */
@IsTest
private class TrxSec_PolicyExclusionsTest {

    @IsTest
    static void exactMatchExcludes() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(userId, TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API)
        };

        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            userId
        );
        Test.stopTest();

        System.assertEquals(true, excluded, 'A matching user and policy key must exclude');
    }

    @IsTest
    static void differentPolicyKeyDoesNotCrossMatch() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(userId, TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_LIST_VIEW)
        };

        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            userId
        );
        Test.stopTest();

        System.assertEquals(
            false,
            excluded,
            'An exclusion for a different policy must not skip this policy'
        );
    }

    @IsTest
    static void policyKeyMatchingIsCaseAndWhitespaceInsensitive() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(userId, '  trxsec_detecttotalaccessapi  ')
        };

        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            'TrxSec_DetectTotalAccessAPI',
            userId
        );
        Test.stopTest();

        System.assertEquals(
            true,
            excluded,
            'Casing and surrounding whitespace on Policy Apex Class must not prevent a match'
        );
    }

    @IsTest
    static void commaSeparatedKeyListMatchesEachEntry() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(
                userId,
                TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API +
                    ', ' +
                    TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_LIST_VIEW
            )
        };

        Test.startTest();
        Boolean apiExcluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            userId
        );
        Boolean listViewExcluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_LIST_VIEW,
            userId
        );
        Boolean reportExcluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_REPORT_EXPORT,
            userId
        );
        Test.stopTest();

        System.assertEquals(true, apiExcluded, 'First comma-separated key must match');
        System.assertEquals(true, listViewExcluded, 'Second comma-separated key must match');
        System.assertEquals(
            false,
            reportExcluded,
            'A policy that is not in the comma-separated list must not be excluded'
        );
    }

    @IsTest
    static void blankAndMalformedUserIdsAreIgnored() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(null, TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API),
            exclusion('not-an-id', TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API),
            exclusion('   ', TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API)
        };

        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            userId
        );
        Test.stopTest();

        System.assertEquals(
            false,
            excluded,
            'Blank or malformed User ID values must be skipped rather than excluding anyone'
        );
    }

    @IsTest
    static void fifteenCharacterUserIdNormalizesAndMatches() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(String.valueOf(userId).substring(0, 15), TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API)
        };

        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            userId
        );
        Test.stopTest();

        System.assertEquals(
            true,
            excluded,
            'A 15-character User ID pasted from a URL must match the 18-character event UserId'
        );
    }

    @IsTest
    static void nullUserIdAndBlankPolicyKeyReturnFalse() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(userId, TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API)
        };

        Test.startTest();
        Boolean nullUser = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            null
        );
        Boolean blankKey = TrxSec_PolicyExclusions.isExcluded('', userId);
        Boolean whitespaceKey = TrxSec_PolicyExclusions.isExcluded('   ', userId);
        Test.stopTest();

        System.assertEquals(false, nullUser, 'A null event user must not be treated as excluded');
        System.assertEquals(false, blankKey, 'A blank policy key must not be treated as excluded');
        System.assertEquals(
            false,
            whitespaceKey,
            'A whitespace-only policy key must not be treated as excluded'
        );
    }

    @IsTest
    static void noConfigurationReturnsFalse() {
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>();

        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            UserInfo.getUserId()
        );
        Test.stopTest();

        System.assertEquals(
            false,
            excluded,
            'With no exclusion records the policy must keep enforcing'
        );
    }

    @IsTest
    static void blankPolicyApexIsIgnored() {
        Id userId = UserInfo.getUserId();
        TrxSec_PolicyExclusions.overridesForTest = new List<Policy_Exclusion__mdt>{
            exclusion(String.valueOf(userId), null),
            exclusion(String.valueOf(userId), '   ')
        };

        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            userId
        );
        Test.stopTest();

        System.assertEquals(
            false,
            excluded,
            'A record with a blank Policy Apex Class must not exclude anyone'
        );
    }

    @IsTest
    static void getAllPathReturnsFalseWhenNoPackagedRecords() {
        Test.startTest();
        Boolean excluded = TrxSec_PolicyExclusions.isExcluded(
            TrxSec_PolicyExclusions.POLICY_TOTAL_ACCESS_API,
            UserInfo.getUserId()
        );
        Test.stopTest();

        System.assertEquals(
            false,
            excluded,
            'The packaged org ships no Policy Exclusion records, so getAll() must not exclude anyone'
        );
    }

    private static Policy_Exclusion__mdt exclusion(String userId, String policyApex) {
        return new Policy_Exclusion__mdt(
            User_ID__c = userId,
            Policy_Apex__c = policyApex
        );
    }
}
