using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

internal static class SafeSummaryTestData
{
    public const string Canary = "PRIVATE-CANARY-6f7389";

    public static DiagnosticReportV3 Create(string sessionId = "safe-summary-session")
    {
        DateTimeOffset start = new(2026, 8, 16, 12, 34, 56, TimeSpan.Zero);
        var fingerprint = new IncidentFingerprint(new string('a', 64));
        var incident = new IncidentCandidate(
            fingerprint,
            start.AddMinutes(2),
            IncidentKind.Bugcheck,
            Canary + " title",
            Canary + " source",
            1001,
            Canary + " target",
            "0x00000116",
            Canary + ".dmp",
            100,
            2,
            start.AddMinutes(2),
            start.AddMinutes(2));
        var target = new TargetProfile(
            Canary + " id",
            Canary + " display",
            ["ExampleGame"],
            [Canary + " related"],
            [Canary + " app signal"],
            [Canary + " artifact signal"],
            [Canary + " reliability signal"],
            Canary + " output");
        var snapshot = new SystemSnapshot(
            start,
            Canary + " computer manufacturer",
            Canary + " computer model",
            Canary + " board maker",
            Canary + " board product",
            Canary + " BIOS",
            Canary + " BIOS date",
            "AMD Ryzen 7 7700X 8-Core Processor",
            64UL * 1024 * 1024 * 1024,
            [new MemoryModuleInfo(32UL * 1024 * 1024 * 1024, 6000, 6000, Canary, Canary)],
            [new GpuInfo("AMD Radeon RX 6700 XT", Canary, 12UL * 1024 * 1024 * 1024), new GpuInfo(Canary + " C:\\Users\\Alice", Canary, null)],
            "Microsoft Windows 11 Pro",
            "10.0.26200",
            "26200.8875",
            "64-bit",
            Canary + " channel",
            true,
            start.AddHours(-2));
        var whea = new DiagnosticEvent(
            start.AddMinutes(2),
            "System",
            WheaEventCatalog.ProviderName,
            WheaEventCatalog.ProviderGuid,
            18,
            2,
            Canary + " level",
            Canary + " WHEA message C:\\Users\\Alice",
            new Dictionary<string, string> { [Canary + " key"] = Canary + " value" });
        var appCrash = new DiagnosticEvent(
            start.AddMinutes(1),
            "Application",
            "Application Error",
            null,
            1000,
            2,
            Canary,
            Canary + " crash message",
            new Dictionary<string, string> { ["FaultingApplicationPath"] = "C:\\Users\\Alice\\private.exe" });
        var bugcheck = new BugcheckRecord(
            start.AddMinutes(2),
            BugcheckEvidenceSource.WindowsErrorReporting,
            Canary + " provider",
            1001,
            Canary + " raw code",
            0x116,
            "0x00000116",
            [1, 2, 3, 4],
            Canary + ".dmp",
            "C:\\Users\\Alice\\" + Canary + ".dmp",
            "C:\\Windows\\MEMORY.DMP");
        var readiness = new CrashReadiness(
            CapturedUtc: start,
            DumpMode: CrashDumpMode.AutomaticMemory,
            RawDumpMode: 7,
            EventLoggingEnabled: true,
            AutoRebootEnabled: true,
            OverwriteEnabled: true,
            AlwaysKeepMemoryDump: false,
            DedicatedDumpFileConfigured: false,
            DumpFileLocation: "C:\\Windows\\MEMORY.DMP " + Canary,
            MinidumpDirectory: "C:\\Windows\\Minidump " + Canary,
            PageFileEntryCount: 1,
            SystemManagedPageFile: true,
            SystemDriveFreeBytes: 100L * 1024 * 1024 * 1024,
            SystemDriveTotalBytes: 1L * 1024 * 1024 * 1024 * 1024,
            Assessment: CrashReadinessState.Ready,
            AssessmentDetail: Canary + " readiness detail",
            DumpDestinationAccessible: true,
            DumpDestinationFreeBytes: 100L * 1024 * 1024 * 1024,
            ActivationState: CrashCaptureActivationState.Active,
            RequiredDumpBackingBytes: 32L * 1024 * 1024 * 1024);
        var dump = new DumpCandidate(
            DumpKind.WindowsMemoryDump,
            Canary + " dump source",
            Canary + ".dmp",
            "C:\\Users\\Alice\\" + Canary + ".dmp",
            4L * 1024 * 1024 * 1024,
            start,
            DumpFormat.PageDump64,
            DumpInspectionState.Recognized,
            64,
            true,
            Canary + " dump detail",
            "C:\\Windows\\MEMORY.DMP");
        var debugger = new DebuggerAnalysis(
            DebuggerAnalysisState.Completed,
            start,
            start.AddSeconds(3),
            SymbolAccessMode.LocalOnly,
            Canary + " debugger version",
            new string('b', 64),
            "0x116",
            [Canary + " param"],
            "VIDEO_TDR_FAILURE_nvlddmkm!unknown_function",
            "nvlddmkm.sys",
            "nvlddmkm.sys",
            "examplegame.exe",
            "loaded",
            ["ntoskrnl.exe", "nvlddmkm.sys"],
            Canary + " debugger limitation",
            "C:\\Users\\Alice\\" + Canary + ".log");

        return new DiagnosticReportV3(
            3,
            "3.2.0-beta.1",
            Canary + " product",
            sessionId,
            DiagnosticMode.Retrospective,
            start,
            start.AddMinutes(5),
            Canary + " completion",
            new IncidentSelection(incident, start.AddDays(-7), start, IncidentSelectionMethod.UserSelected),
            target,
            snapshot,
            snapshot with { CapturedUtc = start.AddMinutes(5) },
            [],
            [whea, appCrash],
            [new DuplicateEventGroup(Canary, WheaEventCatalog.ProviderName, WheaEventCatalog.ProviderGuid, 18, Canary + " grouped message", 3, start, start, [start])],
            [new ReliabilityRecord(start, Canary, Canary, Canary, Canary + " reliability message")],
            [new CrashArtifact(Canary, Canary, "C:\\Users\\Alice\\" + Canary, 100, start, true, "C:\\private")],
            [
                new DiagnosticFinding("bugcheck", 1, FindingSeverity.Critical, FindingConfidence.High, Canary, Canary, Canary, Canary, Canary, Canary),
                new DiagnosticFinding(Canary, 2, FindingSeverity.Warning, FindingConfidence.Low, Canary, Canary, Canary, Canary, Canary, Canary)
            ],
            [new CollectionStatus(Canary, CollectionState.Error, Canary + " collection detail")],
            [new SourceCoverage("Windows Event Log/System", CollectionState.Available, 2, Canary + " coverage detail"), new SourceCoverage(Canary, CollectionState.Error, 1, Canary)],
            [bugcheck],
            readiness,
            new DumpInventory([dump], [new CollectionStatus(Canary, CollectionState.Available, Canary)]),
            new DriverInventory(start, [new DriverDeviceRecord(Canary, Canary, Canary, Canary, Canary, start, Canary, true, Canary)], []),
            null,
            debugger,
            fingerprint,
            Canary + " report summary C:\\Users\\Alice",
            new DumpQuality(start, DumpQualityClassification.Valid, DumpFormat.PageDump64, DumpInternalQualityState.HeaderOnly, true, true, null, DumpChkState.NotFound, Canary, Canary),
            new RecentChangeTimeline(start, start.AddDays(-7), start, [new RecentSystemChange(start, RecentChangeKind.WindowsUpdate, "2026 update KB5030219 " + Canary, Canary, "Succeeded", Canary, TimeSpan.FromHours(1), true, true)], []),
            new StorageHealthSnapshot(start, [new StorageHealthRecord(0, Canary + " drive", "SSD", "NVMe", Canary + " firmware", "Healthy", [Canary], 1_000_000, 50, 70, 5, 0, 0, 0, 0, 10, 20, 30, 100)], []),
            new DriverVerifierState(start, DriverVerifierStatusKind.Enabled, "0x00000009", ["nvlddmkm.sys", Canary + " C:\\bad.sys"], Canary));
    }

    public static async Task<SameIdentityArchiveSubstitution> PrepareSameIdentitySubstitutionAsync(
        string targetPath,
        string replacementPath)
    {
        byte[] replacement = await File.ReadAllBytesAsync(replacementPath);
        long fixedLength = Math.Max(new FileInfo(targetPath).Length, replacement.LongLength) + 8 * 1024;
        await using (var stream = new FileStream(targetPath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            stream.SetLength(fixedLength);
            await stream.FlushAsync();
            stream.Flush(flushToDisk: true);
        }

        DateTime fixedLastWriteUtc = new(2026, 8, 16, 16, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(targetPath, fixedLastWriteUtc);
        fixedLastWriteUtc = File.GetLastWriteTimeUtc(targetPath);
        _ = await BF6CrashDiagnostic.Core.Reporting.IncidentLibrary.ReadValidatedArchiveAsync(targetPath);
        return new SameIdentityArchiveSubstitution(replacement, fixedLength, fixedLastWriteUtc);
    }

    public static async Task ApplySameIdentitySubstitutionAsync(
        string targetPath,
        SameIdentityArchiveSubstitution substitution)
    {
        await using (var stream = new FileStream(targetPath, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            stream.SetLength(0);
            await stream.WriteAsync(substitution.ReplacementBytes);
            stream.SetLength(substitution.FixedLength);
            await stream.FlushAsync();
            stream.Flush(flushToDisk: true);
        }

        File.SetLastWriteTimeUtc(targetPath, substitution.FixedLastWriteUtc);
    }

    internal sealed record SameIdentityArchiveSubstitution(
        byte[] ReplacementBytes,
        long FixedLength,
        DateTime FixedLastWriteUtc);
}
