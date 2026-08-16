using System.Text.Json;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class EvidenceFoundationTests
{
    private static readonly DateTimeOffset IncidentTime =
        new(2026, 8, 2, 4, 42, 18, TimeSpan.Zero);

    [Theory]
    [InlineData("BF6", true)]
    [InlineData("bf6.exe", true)]
    [InlineData("EAAntiCheat.exe", true)]
    [InlineData("Battlefield.exe", false)]
    [InlineData("BF60.exe", false)]
    public void TargetProfile_MatchesOnlyExactProcessNames(string processName, bool expected)
    {
        Assert.Equal(expected, TargetProfile.Battlefield6.MatchesProcessName(processName));
    }

    [Theory]
    [InlineData("Faulting application BF6.exe", true)]
    [InlineData("Crash-Battlefield6-report", true)]
    [InlineData("Faulting application BF60.exe", false)]
    [InlineData("NotBattlefield6Helper.exe", false)]
    public void TargetProfile_ApplicationSignalsRequireTextBoundaries(string text, bool expected)
    {
        Assert.Equal(expected, TargetProfile.Battlefield6.MatchesApplicationEvidence(text));
    }

    [Fact]
    public void IncidentFingerprint_IsDeterministicAndSensitiveToIdentityFields()
    {
        IncidentFingerprint first = IncidentFingerprint.Create(
            IncidentKind.Bugcheck,
            IncidentTime,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            "battlefield-6",
            "0x00000119");
        IncidentFingerprint repeated = IncidentFingerprint.Create(
            IncidentKind.Bugcheck,
            IncidentTime,
            " microsoft-windows-wer-systemerrorreporting ",
            1001,
            "BATTLEFIELD-6",
            "0x00000119");
        IncidentFingerprint changed = IncidentFingerprint.Create(
            IncidentKind.Bugcheck,
            IncidentTime.AddSeconds(1),
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            "battlefield-6",
            "0x00000119");

        Assert.Equal(first, repeated);
        Assert.NotEqual(first, changed);
        Assert.Matches("^[0-9a-f]{64}$", first.Value);
    }

    [Fact]
    public void BugcheckDecoder_NormalizesWerRecordAndDoesNotSerializeOriginalPath()
    {
        const string originalPath = @"C:\Windows\Minidump\080226-12345-01.dmp";
        DiagnosticEvent diagnosticEvent = Event(
            IncidentTime,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["BugcheckCode"] = "0x119",
                ["BugcheckParameter1"] = "0x2",
                ["BugcheckParameter2"] = "15",
                ["DumpFile"] = originalPath
            });

        Assert.True(BugcheckRecordDecoder.TryDecode(diagnosticEvent, out BugcheckRecord record));
        Assert.Equal(BugcheckEvidenceSource.WindowsErrorReporting, record.EvidenceSource);
        Assert.Equal(0x119U, record.Code);
        Assert.Equal("0x00000119", record.NormalizedCode);
        Assert.Equal((ulong)2, record.Parameters[0]);
        Assert.Equal((ulong)15, record.Parameters[1]);
        Assert.Equal("080226-12345-01.dmp", record.DumpFileName);
        Assert.NotEqual(originalPath, record.RedactedDumpPath);
        Assert.Equal(originalPath, record.OriginalDumpPath);

        string json = JsonSerializer.Serialize(record);
        Assert.DoesNotContain(originalPath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("OriginalDumpPath", json, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("281", true, "0x00000119")]
    [InlineData("0x119", true, "0x00000119")]
    [InlineData("0", false, null)]
    [InlineData("0x0", false, null)]
    [InlineData(null, false, null)]
    public void BugcheckDecoder_KernelPowerRequiresNonzeroBugcheckCode(
        string? code,
        bool expected,
        string? normalized)
    {
        var data = new Dictionary<string, string>();
        if (code is not null)
        {
            data["BugcheckCode"] = code;
        }

        bool decoded = BugcheckRecordDecoder.TryDecode(
            Event(IncidentTime, "Microsoft-Windows-Kernel-Power", 41, data),
            out BugcheckRecord record);

        Assert.Equal(expected, decoded);
        if (expected)
        {
            Assert.Equal(normalized, record.NormalizedCode);
        }
    }

    [Fact]
    public void IncidentDiscovery_ClustersDuplicateSupportingRecordsWithoutDroppingEvidence()
    {
        DiagnosticEvent[] events =
        [
            Event(
                IncidentTime,
                "Microsoft-Windows-WER-SystemErrorReporting",
                1001,
                new Dictionary<string, string>
                {
                    ["BugcheckCode"] = "0x119",
                    ["DumpFile"] = @"C:\Windows\Minidump\test.dmp"
                }),
            Event(
                IncidentTime.AddSeconds(2),
                "Microsoft-Windows-Kernel-Power",
                41,
                new Dictionary<string, string> { ["BugcheckCode"] = "281" }),
            Event(IncidentTime.AddSeconds(4), "EventLog", 6008),
            Event(IncidentTime.AddSeconds(4), "EventLog", 6008)
        ];

        IncidentCandidate candidate = Assert.Single(
            new IncidentDiscovery().Discover(events, targetProfile: TargetProfile.Battlefield6));

        Assert.Equal(IncidentKind.Bugcheck, candidate.Kind);
        Assert.Equal("0x00000119", candidate.BugcheckCode);
        Assert.Equal(4, candidate.SupportingRecordCount);
        Assert.Equal(IncidentTime, candidate.FirstSeenUtc);
        Assert.Equal(IncidentTime.AddSeconds(4), candidate.LastSeenUtc);
    }

    [Fact]
    public void IncidentDiscovery_DoesNotInferUnknownWheaSeverityFromMessageText()
    {
        DiagnosticEvent unknownWhea = Event(
            IncidentTime,
            WheaEventCatalog.ProviderName,
            999,
            message: "fatal uncorrectable hardware error");

        Assert.Empty(new IncidentDiscovery().Discover([unknownWhea]));
    }

    [Fact]
    public void IncidentDiscovery_FindsTargetApplicationCrashAndBuildsBoundedSelection()
    {
        DiagnosticEvent applicationError = Event(
            IncidentTime,
            "Application Error",
            1000,
            new Dictionary<string, string> { ["FaultingApplicationName"] = "BF6.exe" });
        var discovery = new IncidentDiscovery();

        IncidentCandidate candidate = Assert.Single(
            discovery.Discover([applicationError], targetProfile: TargetProfile.Battlefield6));
        IncidentSelection selection = discovery.Select(candidate, IncidentSelectionMethod.UserSelected);

        Assert.Equal(IncidentKind.ApplicationCrash, candidate.Kind);
        Assert.Equal("battlefield-6", candidate.TargetProfileId);
        Assert.Equal(IncidentTime.AddMinutes(-10), selection.WindowStartUtc);
        Assert.Equal(IncidentTime.AddMinutes(5), selection.WindowEndUtc);
    }

    [Fact]
    public void CrashCorrelator_PrefersExactRecordedPathOverCloserDump()
    {
        IncidentCandidate candidate = Candidate(IncidentKind.Bugcheck, "0x00000119");
        var selection = new IncidentSelection(
            candidate,
            IncidentTime.AddMinutes(-10),
            IncidentTime.AddMinutes(10),
            IncidentSelectionMethod.UserSelected);
        const string exactPath = @"C:\Windows\Minidump\exact.dmp";
        BugcheckRecord bugcheck = new(
            IncidentTime,
            BugcheckEvidenceSource.WindowsErrorReporting,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            "0x119",
            0x119,
            "0x00000119",
            [2, null, null, null],
            "exact.dmp",
            @"%SystemRoot%\Minidump\exact.dmp",
            exactPath);
        DumpCandidate closer = Dump("closer.dmp", @"C:\Windows\Minidump\closer.dmp", IncidentTime.AddSeconds(1));
        DumpCandidate exact = Dump("exact.dmp", exactPath, IncidentTime.AddMinutes(4));

        CrashCorrelation result = new CrashCorrelator().Correlate(selection, [bugcheck], [closer, exact]);

        Assert.Same(exact, result.SelectedDump);
        Assert.Equal(CrashCorrelationBasis.ExactRecordedPath, result.Basis);
        Assert.Equal(TimeSpan.FromMinutes(4), result.TimeDelta);
        Assert.Contains("does not establish", result.Limitation, StringComparison.OrdinalIgnoreCase);
    }

    private static DiagnosticEvent Event(
        DateTimeOffset timeUtc,
        string provider,
        int eventId,
        IReadOnlyDictionary<string, string>? data = null,
        string message = "") =>
        new(
            timeUtc,
            "System",
            provider,
            provider == WheaEventCatalog.ProviderName ? WheaEventCatalog.ProviderGuid : null,
            eventId,
            2,
            "Error",
            message,
            data ?? new Dictionary<string, string>());

    private static IncidentCandidate Candidate(IncidentKind kind, string? bugcheckCode) =>
        new(
            IncidentFingerprint.Create(kind, IncidentTime, "Test", 1, discriminator: bugcheckCode),
            IncidentTime,
            kind,
            "Test incident",
            "Test",
            1,
            null,
            bugcheckCode,
            null,
            1,
            1,
            IncidentTime,
            IncidentTime);

    private static DumpCandidate Dump(string name, string originalPath, DateTimeOffset lastWriteUtc) =>
        new(
            DumpKind.WindowsMinidump,
            "Test",
            name,
            @"%SystemRoot%\Minidump\" + name,
            32,
            lastWriteUtc,
            DumpFormat.MiniDump,
            DumpInspectionState.Recognized,
            32,
            true,
            "Recognized.",
            originalPath);
}
