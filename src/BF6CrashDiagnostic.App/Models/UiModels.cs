namespace BF6CrashDiagnostic.App.Models;

internal enum WorkflowView
{
    Start,
    Collecting,
    Results,
    ReviewExport
}

internal enum StartPanel
{
    None,
    Incident,
    Monitor,
    PreviousReports
}

internal enum UiIncidentKind
{
    SystemCrash,
    ApplicationCrashOrFreeze
}

internal enum UiTargetKind
{
    Battlefield6Preset,
    Executable,
    RunningProcess
}

internal enum FindingImpact
{
    SystemFailure,
    NeedsReview,
    Information,
    Context
}

internal enum FindingEvidenceStrength
{
    ConfirmedRecord,
    StrongSignal,
    LimitedSignal
}

internal enum UiCrashReadinessLevel
{
    Ready,
    Limited,
    AtRisk,
    Off,
    PendingRestart,
    Unavailable
}

internal enum UiCrashPreparationPreset
{
    Recommended
}

internal enum UiCrashPreparationState
{
    NotStarted,
    Succeeded,
    PendingRestart,
    RolledBack,
    Failed,
    Unavailable
}

internal sealed record UiTargetProfile(
    string Id,
    string DisplayName,
    IReadOnlyList<string> ProcessNames,
    IReadOnlyList<string> RelatedSignals,
    bool BlockSensitiveOperationsWhileRunning,
    UiTargetKind Kind,
    string? SourcePath = null)
{
    public static UiTargetProfile Battlefield6 { get; } = new(
        "battlefield-6",
        "Battlefield 6",
        ["BF6"],
        ["BF6", "BF6.exe", "Battlefield 6", "Javelin", "EA AntiCheat"],
        BlockSensitiveOperationsWhileRunning: true,
        UiTargetKind.Battlefield6Preset);

    public string ProcessSummary => ProcessNames.Count switch
    {
        0 => "No process name selected",
        1 => $"Watches {ProcessNames[0]}.exe",
        _ => $"Watches {string.Join(", ", ProcessNames.Select(name => name + ".exe"))}"
    };
}

internal sealed record UiRunningProcess(int ProcessId, string ProcessName, string DisplayText);

internal sealed record UiIncidentSearchOptions(
    UiIncidentKind IncidentKind,
    UiTargetProfile? Target,
    TimeSpan Lookback);

internal sealed record UiLookbackOption(string Label, TimeSpan Duration);

internal sealed record UiIncidentCandidate(
    string CandidateId,
    UiIncidentKind IncidentKind,
    DateTimeOffset? AnchorUtc,
    string DisplayText,
    string Detail,
    string Source,
    UiTargetProfile? Target = null,
    bool IsSearchPlaceholder = false);

internal sealed record UiIncidentSelection(
    string CandidateId,
    UiIncidentKind IncidentKind,
    DateTimeOffset? AnchorUtc,
    UiTargetProfile? Target);

internal sealed record UiPreviousReport(
    string ReportId,
    DateTimeOffset CreatedUtc,
    string DisplayText,
    string Detail,
    string ZipPath);

internal sealed record UiRecurringIncidentGroup(
    string Title,
    string Detail);

internal sealed record UiIncidentHistory(
    IReadOnlyList<UiPreviousReport> Reports,
    IReadOnlyList<UiRecurringIncidentGroup> RecurringGroups,
    IReadOnlyList<string> CollectionIssues);

internal sealed record UiFinding(
    int Rank,
    FindingImpact Impact,
    FindingEvidenceStrength EvidenceStrength,
    string Title,
    string Evidence,
    string Interpretation,
    string DoesNotEstablish,
    string NextCheck,
    int OccurrenceCount = 1,
    DateTimeOffset? FirstSeen = null,
    DateTimeOffset? LastSeen = null);

public sealed record UiTelemetrySample(
    DateTimeOffset Timestamp,
    double? SystemRamPercent,
    double? CommitPercent,
    double? TargetPrivateGiB,
    double? TargetGpuGiB);

internal sealed record UiSystemFact(string Label, string Value, string? Hint = null);

internal sealed record UiSystemSnapshot(
    IReadOnlyList<UiSystemFact> Facts,
    IReadOnlyList<string> CollectionIssues,
    int AvailableSourceCount,
    int TotalSourceCount);

internal sealed record UiDiagnosticProgress(
    string Stage,
    string Message,
    double? Percent = null,
    string? CollectionIssue = null);

internal sealed record UiDiagnosticResult(
    string SessionId,
    string Summary,
    string ReportZipPath,
    string ReportFolder,
    string? ChecksumPath,
    IReadOnlyList<UiFinding> Findings,
    IReadOnlyList<string> CollectionIssues,
    int AvailableSourceCount,
    int TotalSourceCount,
    string IncidentTitle,
    string TargetDisplayName,
    string CompletionDetail,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    bool CanPackageDump,
    string? EligibleDumpPath = null,
    IReadOnlyList<UiDumpChoice>? DumpChoices = null,
    bool CanRunDebugger = false,
    bool CanRetryWithMicrosoftSymbols = false,
    IReadOnlyList<UiProtectedEvidenceSourceChoice>? ProtectedEvidenceSources = null,
    UiCrashReadiness? CrashReadiness = null,
    bool IsHistoricalReport = false,
    bool CanOfferPerAppCrashCapture = false,
    string? TargetProfileId = null,
    IReadOnlyList<string>? TargetExecutableNames = null,
    bool CanRunDumpCheck = false);

internal sealed record UiCrashReadiness(
    UiCrashReadinessLevel Level,
    string Status,
    string DumpType,
    string Detail,
    string BackingStorage,
    string FreeSpace,
    string EventLogging,
    string AutomaticRestart,
    DateTimeOffset? CapturedUtc,
    bool IsHistorical,
    bool PendingRestart = false)
{
    public static UiCrashReadiness Missing(DateTimeOffset? capturedUtc, bool isHistorical) => new(
        UiCrashReadinessLevel.Unavailable,
        "Unavailable",
        "Not recorded",
        isHistorical
            ? "This older report did not store Windows crash-capture settings."
            : "Windows crash-capture settings could not be read.",
        "Not confirmed",
        "Not confirmed",
        "Not confirmed",
        "Not confirmed",
        capturedUtc,
        isHistorical);
}

internal sealed record UiCrashPreparationPreview(
    string PlanId,
    bool CanProceed,
    string CurrentSummary,
    string ProposedSummary,
    IReadOnlyList<string> Changes,
    string DiskImpact,
    string PrivacyImpact,
    string RestartImpact,
    bool IncludesPerAppCapture,
    string PerAppCaptureSummary,
    string BlockedReason,
    string Heading = "Prepare for the next crash",
    string Introduction = "Review the exact Windows changes before continuing. This cannot add information to a crash dump that already exists.",
    string ActionText = "Continue to Windows UAC",
    string UacNotice = "Windows will show a UAC prompt after you continue.")
{
    public static UiCrashPreparationPreview Unavailable(string reason) => new(
        string.Empty,
        false,
        "Current settings were not changed.",
        "No preparation plan is available.",
        [],
        "No disk changes were made.",
        "No crash-dump settings were changed.",
        "No restart is required because nothing changed.",
        false,
        string.Empty,
        reason);
}

internal sealed record UiCrashPreparationOutcome(
    UiCrashPreparationState State,
    string Message,
    UiCrashReadiness? VerifiedReadiness = null,
    UiDiagnosticResult? UpdatedResult = null,
    string? ReceiptId = null,
    bool CanRestore = false);

internal sealed record UiRestorablePerAppCaptureReceipt(
    string ReceiptId,
    string ExecutableName,
    string DisplayName,
    DateTimeOffset AppliedUtc,
    string? TargetProfileId,
    IReadOnlyList<string> TargetExecutableNames);

internal sealed record UiRestorableConfigurationReceipts(
    string? CrashCaptureReceiptId,
    IReadOnlyList<UiRestorablePerAppCaptureReceipt> PerAppCaptureReceipts,
    IReadOnlyList<string> Warnings)
{
    public static UiRestorableConfigurationReceipts Empty { get; } = new(null, [], []);
}

internal sealed record UiDumpChoice(
    string Name,
    string Kind,
    string Size,
    string Detail,
    string Path,
    bool RequiresAdministratorAccess = false);

internal sealed record UiProtectedEvidenceSourceChoice(
    string SourceId,
    string DisplayName,
    string Detail);

internal sealed record UiProtectedDumpConsent(
    bool PrivacyConfirmed,
    bool SizeConfirmed,
    bool FreeSpaceConfirmed);

internal sealed record UiProtectedOperationResult(
    bool Succeeded,
    string Message);

internal sealed class MetricCardViewModel(string label, string value, string hint) : BF6CrashDiagnostic.App.ViewModels.ObservableObject
{
    private string _value = value;
    private string _hint = hint;

    public string Label { get; } = label;

    public string Value
    {
        get => _value;
        set => SetProperty(ref _value, value);
    }

    public string Hint
    {
        get => _hint;
        set => SetProperty(ref _hint, value);
    }
}

internal sealed class WorkflowStepViewModel(string number, string title) : BF6CrashDiagnostic.App.ViewModels.ObservableObject
{
    private string _state = "Waiting";
    private bool _isCurrent;
    private bool _isComplete;

    public string Number { get; } = number;

    public string Title { get; } = title;

    public string State
    {
        get => _state;
        set => SetProperty(ref _state, value);
    }

    public bool IsCurrent
    {
        get => _isCurrent;
        set => SetProperty(ref _isCurrent, value);
    }

    public bool IsComplete
    {
        get => _isComplete;
        set => SetProperty(ref _isComplete, value);
    }
}

internal sealed class FindingViewModel(UiFinding finding, int displayRank)
{
    public int Rank { get; } = displayRank;
    public string Impact { get; } = finding.Impact switch
    {
        FindingImpact.SystemFailure => "System failure",
        FindingImpact.NeedsReview => "Needs review",
        FindingImpact.Information => "Information",
        _ => "Context"
    };
    public string EvidenceStrength { get; } = finding.EvidenceStrength switch
    {
        FindingEvidenceStrength.ConfirmedRecord => "Confirmed record",
        FindingEvidenceStrength.StrongSignal => "Strong signal",
        _ => "Limited signal"
    };
    public string Title { get; } = finding.Title;
    public string Evidence { get; } = finding.Evidence;
    public string Interpretation { get; } = finding.Interpretation;
    public string DoesNotEstablish { get; } = finding.DoesNotEstablish;
    public string NextCheck { get; } = finding.NextCheck;
    public string OccurrenceSummary { get; } = CreateOccurrenceSummary(finding);

    private static string CreateOccurrenceSummary(UiFinding finding)
    {
        if (finding.OccurrenceCount <= 1)
        {
            return finding.FirstSeen is null
                ? "1 occurrence"
                : $"1 occurrence · {finding.FirstSeen.Value.ToLocalTime():MMM d, h:mm:ss tt} local";
        }

        string range = string.Empty;
        if (finding.FirstSeen is not null && finding.LastSeen is not null)
        {
            DateTimeOffset first = finding.FirstSeen.Value.ToLocalTime();
            DateTimeOffset last = finding.LastSeen.Value.ToLocalTime();
            string lastText = first.Date == last.Date
                ? last.ToString("h:mm:ss tt")
                : last.ToString("MMM d, h:mm:ss tt");
            range = $" · {first:MMM d, h:mm:ss tt} – {lastText} local";
        }
        return $"{finding.OccurrenceCount} matching occurrences{range}";
    }
}
