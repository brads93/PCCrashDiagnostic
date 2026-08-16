using System.Globalization;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

/// <summary>
/// Produces an in-memory schema-3 view of a validated legacy schema-2 report. The source
/// archive is never changed or rewritten. Free-form legacy fields remain outside the typed
/// sharing projection; only the normal schema-3 allowlist can reach Safe Summary output.
/// </summary>
public static class LegacyV2ReportAdapter
{
    public static DiagnosticReportV3 ToDiagnosticReportV3(DiagnosticReport legacy)
    {
        ArgumentNullException.ThrowIfNull(legacy);
        if (legacy.ReportSchemaVersion != 2 || !SessionIdValidator.IsValid(legacy.SessionId))
        {
            throw new InvalidDataException("The validated legacy report identity is invalid.");
        }

        IncidentSelection? selection = CreateSelection(legacy.Anchor, legacy.StartUtc, legacy.EndUtc);
        IReadOnlyList<BugcheckRecord> bugchecks = CreateBugchecks(legacy);
        TargetPerformanceSample[] samples = (legacy.Samples ?? [])
            .Select(item => new TargetPerformanceSample(
                item.TimestampUtc,
                item.BF6Running,
                item.BF6Running ? 1 : 0,
                item.SystemCpuPct,
                item.SystemMemoryUsedGB,
                item.SystemMemoryAvailableGB,
                item.SystemCommittedGB,
                item.SystemCommitLimitGB,
                item.SystemCommitPct,
                item.BF6WorkingSetMB,
                item.BF6PrivateMB,
                item.BF6CpuPct,
                item.BF6Gpu3DPct,
                item.BF6GpuMaxEnginePct,
                item.BF6DedicatedGpuMB,
                item.BF6SharedGpuMB,
                item.SampleCollectionMs))
            .ToArray();
        SourceCoverage[] coverage = (legacy.CollectionStatus ?? [])
            .Select(item => new SourceCoverage(item.Source, item.State, 0, string.Empty))
            .ToArray();

        return new DiagnosticReportV3(
            3,
            legacy.ToolVersion,
            "PC Crash Diagnostic",
            legacy.SessionId,
            legacy.Mode,
            legacy.StartUtc,
            legacy.EndUtc,
            legacy.CompletionReason,
            selection,
            TargetProfile.Battlefield6,
            legacy.StartSnapshot,
            legacy.EndSnapshot,
            samples,
            legacy.Events ?? [],
            legacy.EventGroups ?? [],
            legacy.Reliability ?? [],
            legacy.Artifacts ?? [],
            legacy.Findings ?? [],
            legacy.CollectionStatus ?? [],
            coverage,
            bugchecks,
            null,
            new DumpInventory([], []),
            null,
            null,
            null,
            selection?.Candidate.Fingerprint,
            legacy.Summary)
        {
            WheaEvidence = WheaEvidenceSummarizer.Summarize(legacy.Events ?? [])
        };
    }

    private static IncidentSelection? CreateSelection(
        CrashAnchor? anchor,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc)
    {
        if (anchor is null)
        {
            return null;
        }

        uint? code = ParseBugcheckCode(anchor.BugCheckCode);
        IncidentKind kind = Classify(anchor, code.HasValue);
        string discriminator = code.HasValue ? $"0x{code.Value:X8}" : string.Empty;
        IncidentFingerprint fingerprint = IncidentFingerprint.Create(
            kind,
            anchor.TimeUtc,
            anchor.Source,
            anchor.EventId,
            TargetProfile.Battlefield6.Id,
            discriminator);
        var candidate = new IncidentCandidate(
            fingerprint,
            anchor.TimeUtc,
            kind,
            "Legacy report incident",
            anchor.Source,
            anchor.EventId,
            TargetProfile.Battlefield6.Id,
            code.HasValue ? $"0x{code.Value:X8}" : null,
            null,
            anchor.Priority,
            1,
            anchor.TimeUtc,
            anchor.TimeUtc,
            IncidentEvidenceOrigin.WindowsEventLog);
        return new IncidentSelection(candidate, startUtc, endUtc, IncidentSelectionMethod.UserSelected);
    }

    private static IReadOnlyList<BugcheckRecord> CreateBugchecks(DiagnosticReport legacy)
    {
        var records = BugcheckRecordDecoder.Decode(legacy.Events ?? []).ToList();
        CrashAnchor? anchor = legacy.Anchor;
        uint? code = ParseBugcheckCode(anchor?.BugCheckCode);
        if (anchor is not null && code.HasValue && !records.Any(item =>
                item.Code == code && item.TimeUtc == anchor.TimeUtc.ToUniversalTime()))
        {
            records.Add(new BugcheckRecord(
                anchor.TimeUtc.ToUniversalTime(),
                IdentifyBugcheckSource(anchor),
                anchor.Source,
                anchor.EventId,
                anchor.BugCheckCode ?? string.Empty,
                code,
                $"0x{code.Value:X8}",
                new ulong?[4],
                null,
                null,
                null,
                BugcheckCatalog.GetName(code.Value)));
        }

        return records
            .OrderBy(item => item.TimeUtc)
            .ThenBy(item => item.EvidenceSource)
            .ToArray();
    }

    private static IncidentKind Classify(CrashAnchor anchor, bool hasBugcheck) => hasBugcheck
        ? IncidentKind.Bugcheck
        : anchor.EventId switch
        {
            41 or 6008 => IncidentKind.UnexpectedRestart,
            1 or 18 or 19 or 20 or 46 or 47 => anchor.Source.Contains("WHEA", StringComparison.OrdinalIgnoreCase)
                ? IncidentKind.HardwareError
                : IncidentKind.Unknown,
            4101 => IncidentKind.GpuTimeout,
            1000 => IncidentKind.ApplicationCrash,
            1002 => IncidentKind.ApplicationHang,
            _ => IncidentKind.Unknown
        };

    private static BugcheckEvidenceSource IdentifyBugcheckSource(CrashAnchor anchor) =>
        anchor.EventId == 1001 || anchor.Source.Contains("SystemErrorReporting", StringComparison.OrdinalIgnoreCase)
            ? BugcheckEvidenceSource.WindowsErrorReporting
            : anchor.EventId == 41
                ? BugcheckEvidenceSource.KernelPower
                : BugcheckEvidenceSource.Unknown;

    private static uint? ParseBugcheckCode(string? value)
    {
        string normalized = value?.Trim() ?? string.Empty;
        NumberStyles style = NumberStyles.Integer;
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized[2..];
            style = NumberStyles.AllowHexSpecifier;
        }

        return normalized.Length > 0 && uint.TryParse(normalized, style, CultureInfo.InvariantCulture, out uint code)
            ? code
            : null;
    }
}
