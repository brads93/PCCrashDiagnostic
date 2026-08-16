using System.Reflection;
using System.Text;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using BF6CrashDiagnostic.Core.Sharing;

namespace PCCrashDiagnostic.Share.Tests;

public sealed class SharingBoundaryTests
{
    [Fact]
    public void SafeSummary_PublicProjectionCannotCopyFreeFormReportText()
    {
        const string canary = "PRIVATE-CANARY-55f32a";
        DateTimeOffset now = new(2026, 8, 16, 12, 0, 0, TimeSpan.Zero);
        var report = new DiagnosticReportV3(
            3,
            "3.2.0-beta.1",
            canary + " product",
            canary + " session",
            DiagnosticMode.Retrospective,
            now,
            now.AddMinutes(1),
            canary + " completion",
            null,
            null,
            null,
            null,
            [],
            [new DiagnosticEvent(now, "Application", "Application Error", null, 1000, 2, canary, canary + " message", new Dictionary<string, string> { [canary] = canary })],
            [],
            [new ReliabilityRecord(now, canary, canary, canary, canary)],
            [new CrashArtifact(canary, canary, "C:\\Users\\Alice\\private.dmp", 10, now, true, "C:\\Users\\Alice\\private.dmp")],
            [new DiagnosticFinding("application-failure", 1, FindingSeverity.Warning, FindingConfidence.Medium, canary, canary, canary, canary, canary, canary)],
            [new CollectionStatus(canary, CollectionState.Error, canary)],
            [new SourceCoverage("Windows Event Log/Application", CollectionState.Available, 1, canary)],
            [],
            null,
            new DumpInventory([], []),
            null,
            null,
            null,
            null,
            canary + " summary");

        string text = SafeSummaryRenderer.Render(SafeSummaryProjector.Project(report));

        Assert.DoesNotContain(canary, text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\Users\\Alice", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Application crash marker", text, StringComparison.Ordinal);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(text) <= SafeSummaryRenderer.MaximumUtf8Bytes);
    }

    [Fact]
    public void PublicSharingApi_RequiresValidatedOpaqueReportHandle()
    {
        Assert.Empty(typeof(UiReportHandle).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Null(typeof(ReportHandleRegistry).GetMethod(
            "Register",
            BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(ReportHandleRegistry).GetMethod(
            nameof(ReportHandleRegistry.RegisterValidatedAsync),
            BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(SafeSummaryService).GetMethod(
            nameof(SafeSummaryService.CreatePreviewAsync),
            BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(SafeSummaryService).GetMethod(
            nameof(SafeSummaryService.GetExactUtf8Async),
            BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(SafeSummaryService).GetMethod(
            nameof(SafeSummaryService.GetExactTextAsync),
            BindingFlags.Public | BindingFlags.Instance));
        Assert.Null(typeof(SafeSummaryService).GetMethod(
            "GetPreviewText",
            BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(
            typeof(SafeSummaryService).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            method => method.Name == "CreatePreview" &&
                      method.GetParameters().Any(parameter => parameter.ParameterType == typeof(DiagnosticReportV3)));
    }

    [Fact]
    public void PublicAssemblies_DoNotExportGuardBypassCollectorOrRunnerTypes()
    {
        Assembly[] publicAssemblies =
        [
            typeof(SafeSummaryService).Assembly,
            typeof(PCCrashDiagnostic.LocalTools.LocalDebuggerService).Assembly
        ];
        string[] forbiddenTypeNames =
        [
            "SafeDumpInspector",
            "MiniDumpMetadataReader",
            "DumpInventoryCollector",
            "DumpQualityCollector",
            "WinDbgRunner"
        ];

        string[] exportedNames = publicAssemblies
            .SelectMany(assembly => assembly.GetExportedTypes())
            .Select(type => type.Name)
            .ToArray();

        foreach (string forbiddenTypeName in forbiddenTypeNames)
        {
            Assert.DoesNotContain(forbiddenTypeName, exportedNames, StringComparer.Ordinal);
        }
    }

    [Fact]
    public void ShareCoreBinary_DoesNotContainAdvancedDumpAccessInstruction()
    {
        byte[] assemblyBytes = File.ReadAllBytes(typeof(SafeSummaryService).Assembly.Location);
        string[] forbiddenPhrases =
        [
            "protected evidence operation",
            "retry the protected evidence",
            "with UAC"
        ];

        foreach (string phrase in forbiddenPhrases)
        {
            Assert.True(
                assemblyBytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(phrase)) < 0 &&
                assemblyBytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes(phrase)) < 0,
                $"The ShareReadOnly Core binary contained the advanced instruction phrase '{phrase}'.");
        }
    }
}
