using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public sealed class CrashCorrelator
{
    public CrashCorrelation Correlate(
        IncidentSelection selection,
        IEnumerable<BugcheckRecord> bugchecks,
        IEnumerable<DumpCandidate> dumps,
        DateTimeOffset? currentBootUtc = null)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ArgumentNullException.ThrowIfNull(bugchecks);
        ArgumentNullException.ThrowIfNull(dumps);

        BugcheckRecord? bugcheck = bugchecks
            .Where(item => item.TimeUtc >= selection.WindowStartUtc && item.TimeUtc <= selection.WindowEndUtc)
            .OrderBy(item => (item.TimeUtc - selection.Candidate.TimeUtc).Duration())
            .ThenBy(item => item.EvidenceSource == BugcheckEvidenceSource.WindowsErrorReporting ? 0 : 1)
            .FirstOrDefault();
        DumpCandidate[] related = dumps
            .Where(item => item.LastWriteUtc >= selection.WindowStartUtc &&
                           item.LastWriteUtc <= selection.WindowEndUtc &&
                           item.InspectionState == DumpInspectionState.Recognized)
            .OrderBy(item => SameBootRank(item, selection, currentBootUtc))
            .ThenBy(item => IncidentDumpPriority(item.Kind, selection.Candidate.Kind))
            .ThenBy(item => (item.LastWriteUtc - selection.Candidate.TimeUtc).Duration())
            .ToArray();

        DumpCandidate? selected = null;
        CrashCorrelationBasis basis = CrashCorrelationBasis.None;
        if (bugcheck?.OriginalDumpPath is not null)
        {
            string expectedPath = SafeFullPath(bugcheck.OriginalDumpPath);
            selected = related.FirstOrDefault(item =>
                item.OriginalPath is not null &&
                string.Equals(SafeFullPath(item.OriginalPath), expectedPath, StringComparison.OrdinalIgnoreCase));
            if (selected is not null)
            {
                basis = CrashCorrelationBasis.ExactRecordedPath;
            }
        }

        if (selected is null && !string.IsNullOrWhiteSpace(bugcheck?.DumpFileName))
        {
            DumpCandidate[] fileNameMatches = related.Where(item =>
                item.Name.Equals(bugcheck.DumpFileName, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (fileNameMatches.Length == 1)
            {
                selected = fileNameMatches[0];
                basis = CrashCorrelationBasis.ExactFileName;
            }
        }

        if (selected is null && related.Length == 1)
        {
            selected = related[0];
            basis = CrashCorrelationBasis.TimestampProximity;
        }

        string limitation = selected is null && related.Length > 1
            ? "More than one dump matched this incident window. The user must select a dump; timestamp ranking alone was not used as a decision."
            : "Correlation identifies nearby records and files; it does not establish the crash cause.";

        return new CrashCorrelation(
            selection.Candidate.Fingerprint,
            bugcheck,
            selected,
            basis,
            selected is null ? null : (selected.LastWriteUtc - selection.Candidate.TimeUtc).Duration(),
            related,
            limitation);
    }

    public CrashCorrelation SelectDump(CrashCorrelation correlation, DumpCandidate selectedDump)
    {
        ArgumentNullException.ThrowIfNull(correlation);
        ArgumentNullException.ThrowIfNull(selectedDump);
        DumpCandidate? allowed = correlation.RelatedDumps.FirstOrDefault(item =>
            string.Equals(item.OriginalPath, selectedDump.OriginalPath, StringComparison.OrdinalIgnoreCase) &&
            item.SizeBytes == selectedDump.SizeBytes &&
            item.LastWriteUtc == selectedDump.LastWriteUtc);
        if (allowed is null)
        {
            throw new InvalidOperationException("The selected dump is not in this incident's validated inventory.");
        }

        return correlation with
        {
            SelectedDump = allowed,
            Basis = CrashCorrelationBasis.UserSelected,
            TimeDelta = null,
            Limitation = "The user selected this dump from the incident inventory. Selection does not establish the crash cause."
        };
    }

    private static int DumpPriority(DumpKind kind) => kind switch
    {
        DumpKind.WindowsMinidump => 0,
        DumpKind.WindowsMemoryDump => 1,
        DumpKind.LiveKernelDump => 2,
        DumpKind.ApplicationDump => 3,
        _ => 4
    };

    private static int IncidentDumpPriority(DumpKind kind, IncidentKind incidentKind) => incidentKind switch
    {
        IncidentKind.ApplicationCrash or IncidentKind.ApplicationHang => kind == DumpKind.ApplicationDump ? 0 : 10 + DumpPriority(kind),
        IncidentKind.GpuTimeout => kind == DumpKind.LiveKernelDump ? 0 : 10 + DumpPriority(kind),
        IncidentKind.Bugcheck or IncidentKind.UnexpectedRestart => kind is DumpKind.WindowsMinidump or DumpKind.WindowsMemoryDump
            ? DumpPriority(kind)
            : 10 + DumpPriority(kind),
        _ => DumpPriority(kind)
    };

    private static int SameBootRank(
        DumpCandidate item,
        IncidentSelection selection,
        DateTimeOffset? bootUtc) =>
        bootUtc is not null && selection.Candidate.TimeUtc >= bootUtc && item.LastWriteUtc >= bootUtc ? 0 : 1;

    private static string SafeFullPath(string path)
    {
        try
        {
            return Path.GetFullPath(path);
        }
        catch (ArgumentException)
        {
            return path;
        }
        catch (NotSupportedException)
        {
            return path;
        }
        catch (IOException)
        {
            return path;
        }
        catch (System.Security.SecurityException)
        {
            return path;
        }
    }
}
