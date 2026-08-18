/**
 * @description Shared helpers for Transaction Security Policy conditions bound to ReportEvent.
 * The export predicate lives here so that every ReportEvent condition applies the same definition
 * of "this was an export" and the conditions cannot drift apart again.
 */
public with sharing class TrxSec_ReportEventUtils {

    private static final String EXPORT_OPERATION_PREFIX = 'ReportExported';

    /**
     * @description Reports whether a ReportEvent.Operation value represents a report export.
     *
     * ReportEvent.Operation is a nillable restricted picklist. It currently defines three export
     * values, all sharing the ReportExported prefix: ReportExported (a printable view or export
     * that was neither asynchronous nor an API export), ReportExportedAsynchronously and
     * ReportExportedUsingExcelConnector. Note that the export FILE FORMAT is not part of Operation;
     * it is carried separately in ExportFileFormat (CSV or Excel).
     *
     * Prefix matching is deliberate, in preference to an allowlist of the three known values. This
     * is a detective security control, so an export value introduced by a future Salesforce release
     * should fail toward being evaluated rather than being silently ignored. An allowlist fails open
     * on any newly added value, which is precisely how these conditions came to miss asynchronous
     * exports in the first place.
     *
     * @param operation The ReportEvent.Operation value to test. May be null or blank.
     * @return true when the operation is an export, false for null, blank and non-export values.
     */
    public static Boolean isReportExportOperation(String operation) {
        // Operation is nillable and the blank check must come first: startsWith on a null value
        // throws a NullPointerException, and an exception escaping a TSP condition has
        // unpredictable enforcement consequences.
        if (String.isBlank(operation)) {
            return false;
        }
        return operation.startsWith(EXPORT_OPERATION_PREFIX);
    }
}
