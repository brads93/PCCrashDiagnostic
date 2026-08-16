using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

public sealed class ReportHandleRegistryTests
{
    [Fact]
    public async Task RegisterValidatedCopies_BindsMixedAppLocalOrigins_AndRejectsExternalOriginal()
    {
        using var appData = new TestDirectory();
        using var external = new TestDirectory();
        ReportPackageV3 generated = await new ReportWriter(appData.Path).WriteV3Async(
            SafeSummaryTestData.Create("mixed-copy-session"));
        ReportPackageV3 source = await new ReportWriter(external.Path).WriteV3Async(
            SafeSummaryTestData.Create("mixed-copy-session"));
        var library = new IncidentLibrary(appData.Path);
        ReportImportResult imported = Assert.Single(await library.ImportValidatedReportsAsync([source.ZipPath]));
        Assert.True(imported.Imported);
        var registry = new ReportHandleRegistry(appData.Path);

        UiReportHandle handle = await registry.RegisterValidatedCopiesAsync(
        [
            new LocalReportCopy(generated.ZipPath, Imported: false),
            new LocalReportCopy(imported.ImportedPath!, Imported: true)
        ]);

        ResolvedReportHandle resolved = registry.Resolve(handle);
        Assert.Equal(2, resolved.Files.Count);
        Assert.Contains(resolved.Files, file => file.Origin == ReportOrigin.Generated);
        Assert.Contains(resolved.Files, file => file.Origin == ReportOrigin.Imported);
        Assert.True(registry.IsValid(handle));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            registry.RegisterValidatedCopiesAsync(
                [new LocalReportCopy(source.ZipPath, Imported: true)]));
    }

    [Fact]
    public void Register_ReturnsOpaqueHandle_AndRejectsChangedFile()
    {
        using var directory = new TestDirectory();
        string reports = Path.Combine(directory.Path, "Reports");
        Directory.CreateDirectory(reports);
        string report = Path.Combine(reports, "report.zip");
        File.WriteAllBytes(report, [1, 2, 3, 4]);
        var registry = new ReportHandleRegistry(directory.Path);

        UiReportHandle handle = registry.Register("session-1", ReportOrigin.Generated, [report]);

        Assert.True(registry.IsValid(handle));
        Assert.Equal("PC Crash Diagnostic report", handle.ToString());
        Assert.DoesNotContain(report, handle.ToString(), StringComparison.OrdinalIgnoreCase);

        File.Delete(report);
        File.WriteAllBytes(report, [9, 8, 7, 6, 5, 4]);

        Assert.False(registry.IsValid(handle));
    }

    [Fact]
    public void Register_RejectsPathOutsideOriginRoot()
    {
        using var directory = new TestDirectory();
        string reports = Path.Combine(directory.Path, "Reports");
        Directory.CreateDirectory(reports);
        string outside = Path.Combine(directory.Path, "outside.zip");
        File.WriteAllBytes(outside, [1]);
        var registry = new ReportHandleRegistry(directory.Path);

        Assert.Throws<UnauthorizedAccessException>(() =>
            registry.Register("session-1", ReportOrigin.Generated, [outside]));
    }

    [Fact]
    public void Register_EnforcesOriginSpecificRoot()
    {
        using var directory = new TestDirectory();
        string reports = Path.Combine(directory.Path, "Reports");
        Directory.CreateDirectory(reports);
        string report = Path.Combine(reports, "report.zip");
        File.WriteAllBytes(report, [1]);
        var registry = new ReportHandleRegistry(directory.Path);

        Assert.Throws<UnauthorizedAccessException>(() =>
            registry.Register("session-1", ReportOrigin.Imported, [report]));
    }

    [Fact]
    public void Register_MoreThanBoundedCopyLimit_FailsClosedWithoutTruncating()
    {
        using var directory = new TestDirectory();
        string reports = Path.Combine(directory.Path, "Reports");
        Directory.CreateDirectory(reports);
        string[] paths = Enumerable.Range(0, 257)
            .Select(index => Path.Combine(reports, $"report-{index:D3}.zip"))
            .ToArray();
        foreach (string path in paths)
        {
            File.WriteAllBytes(path, [1]);
        }

        var registry = new ReportHandleRegistry(directory.Path);

        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            registry.Register("session-1", ReportOrigin.Generated, paths));
        Assert.Contains("256", exception.Message, StringComparison.Ordinal);
    }
}
