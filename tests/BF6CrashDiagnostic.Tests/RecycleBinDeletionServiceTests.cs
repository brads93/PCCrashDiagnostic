using BF6CrashDiagnostic.Core.Reporting;
using BF6CrashDiagnostic.Core.Sharing;

namespace BF6CrashDiagnostic.Tests;

public sealed class RecycleBinDeletionServiceTests
{
    [Fact]
    public async Task LogicalHistoryDeletion_RecyclesEveryAppLocalCopy_LeavesImportSource_AndRevokesSummary()
    {
        using var appData = new TestDirectory();
        using var external = new TestDirectory();
        const string sessionId = "logical-history-session";
        ReportPackageV3 generated = await new ReportWriter(appData.Path).WriteV3Async(
            SafeSummaryTestData.Create(sessionId));
        ReportPackageV3 externalSource = await new ReportWriter(external.Path).WriteV3Async(
            SafeSummaryTestData.Create(sessionId));
        var library = new IncidentLibrary(appData.Path);
        ReportImportResult imported = Assert.Single(await library.ImportValidatedReportsAsync([externalSource.ZipPath]));
        IncidentLibraryEntry incident = Assert.Single((await library.BuildAsync()).Incidents);
        IReadOnlyList<LocalReportCopy> localCopies = Assert.IsAssignableFrom<IReadOnlyList<LocalReportCopy>>(
            incident.LocalCopies);
        Assert.Equal(2, localCopies.Count);
        Assert.DoesNotContain(localCopies, copy => string.Equals(
            copy.ReportPath,
            externalSource.ZipPath,
            StringComparison.OrdinalIgnoreCase));

        var registry = new ReportHandleRegistry(appData.Path);
        UiReportHandle handle = await registry.RegisterValidatedCopiesAsync(localCopies);
        var summaries = new SafeSummaryService();
        SafeSummaryPreview summary = await summaries.CreatePreviewAsync(handle, registry);
        var adapter = new MovingRecycleAdapter(Path.Combine(appData.Path, "FakeRecycle"));
        var service = new RecycleBinDeletionService(appData.Path, registry, adapter, summaries);

        ReportDeletionPreview preview = service.PreviewSelected(handle);

        Assert.Equal(3, preview.ReportFileCount);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            summaries.GetExactTextAsync(summary.PreviewToken));
        ReportDeletionResult result = await service.RecycleAsync(preview.PreviewToken);
        Assert.Equal(ReportDeletionState.Recycled, result.State);
        Assert.False(File.Exists(generated.ZipPath));
        Assert.False(File.Exists(generated.Sha256Path));
        Assert.False(File.Exists(imported.ImportedPath));
        Assert.True(File.Exists(externalSource.ZipPath));
        Assert.False(registry.IsValid(handle));
    }

    [Fact]
    public async Task SelectedReport_IsMovedOnlyThroughRecycleAdapter()
    {
        using var directory = new TestDirectory();
        (string report, UiReportHandle handle, ReportHandleRegistry registry) = CreateReport(directory.Path);
        string checksum = report + ".sha256";
        File.WriteAllText(checksum, "checksum");
        string session = Path.Combine(directory.Path, "Sessions", "session-1");
        Directory.CreateDirectory(session);
        File.WriteAllText(Path.Combine(session, "Report.json"), "{}");
        var adapter = new MovingRecycleAdapter(Path.Combine(directory.Path, "FakeRecycle"));
        var service = new RecycleBinDeletionService(directory.Path, registry, adapter);
        ReportDeletionPreview preview = service.PreviewSelected(handle);

        ReportDeletionResult result = await service.RecycleAsync(preview.PreviewToken);

        Assert.Equal(ReportDeletionState.Recycled, result.State);
        Assert.Equal(3, result.RecycledItemCount);
        Assert.False(File.Exists(report));
        Assert.False(File.Exists(checksum));
        Assert.False(Directory.Exists(session));
        Assert.Equal(3, adapter.Paths.Count);
        Assert.False(registry.IsValid(handle));
    }

    [Fact]
    public async Task UnavailableRecycleBin_LeavesSourceAndUsesNoFallback()
    {
        using var directory = new TestDirectory();
        (string report, UiReportHandle handle, ReportHandleRegistry registry) = CreateReport(directory.Path);
        var adapter = new StaticRecycleAdapter(RecycleBinAdapterState.Unavailable);
        var service = new RecycleBinDeletionService(directory.Path, registry, adapter);
        ReportDeletionPreview preview = service.PreviewSelected(handle);

        ReportDeletionResult result = await service.RecycleAsync(preview.PreviewToken);

        Assert.Equal(ReportDeletionState.RecycleBinUnavailable, result.State);
        Assert.True(File.Exists(report));
        Assert.Equal(1, adapter.CallCount);
        Assert.Contains("No permanent-delete fallback", result.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ChangedTarget_FailsBeforeCallingRecycleAdapter()
    {
        using var directory = new TestDirectory();
        (string report, UiReportHandle handle, ReportHandleRegistry registry) = CreateReport(directory.Path);
        var adapter = new StaticRecycleAdapter(RecycleBinAdapterState.Recycled);
        var service = new RecycleBinDeletionService(directory.Path, registry, adapter);
        ReportDeletionPreview preview = service.PreviewSelected(handle);
        await File.AppendAllTextAsync(report, "changed");

        ReportDeletionResult result = await service.RecycleAsync(preview.PreviewToken);

        Assert.Equal(ReportDeletionState.FilesChanged, result.State);
        Assert.Equal(0, adapter.CallCount);
        Assert.True(File.Exists(report));
    }

    [Fact]
    public async Task AllHistory_IncludesOnlyValidatedReportsAndTheirChecksums()
    {
        using var directory = new TestDirectory();
        string reports = Path.Combine(directory.Path, "Reports");
        ReportPackageV3 package = await new ReportWriter(directory.Path).WriteV3Async(SafeSummaryTestData.Create());
        File.WriteAllBytes(Path.Combine(reports, "unrelated.zip"), [1]);
        File.WriteAllText(Path.Combine(reports, "notes.txt"), "keep");
        var registry = new ReportHandleRegistry(directory.Path);
        var service = new RecycleBinDeletionService(
            directory.Path,
            registry,
            new StaticRecycleAdapter(RecycleBinAdapterState.Recycled));

        ReportDeletionPreview preview = await service.PreviewAllHistoryAsync();

        Assert.Equal(2, preview.ReportFileCount);
        Assert.Equal(2, preview.ExcludedItemCount);
        Assert.True(File.Exists(package.ZipPath));
        Assert.True(File.Exists(package.Sha256Path));
        Assert.True(File.Exists(Path.Combine(reports, "unrelated.zip")));
    }

    private static (string Report, UiReportHandle Handle, ReportHandleRegistry Registry) CreateReport(string root)
    {
        string reports = Path.Combine(root, "Reports");
        Directory.CreateDirectory(reports);
        string report = Path.Combine(reports, "report.zip");
        File.WriteAllBytes(report, [1, 2, 3]);
        var registry = new ReportHandleRegistry(root);
        UiReportHandle handle = registry.Register("session-1", ReportOrigin.Generated, [report]);
        return (report, handle, registry);
    }

    private sealed class StaticRecycleAdapter(RecycleBinAdapterState state) : IRecycleBinAdapter
    {
        public int CallCount { get; private set; }

        public Task<RecycleBinAdapterResult> RecycleAsync(
            string path,
            FileTreeSnapshot expectedSnapshot,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CallCount++;
            return Task.FromResult(new RecycleBinAdapterResult(state));
        }
    }

    private sealed class MovingRecycleAdapter(string recycleRoot) : IRecycleBinAdapter
    {
        public List<string> Paths { get; } = [];

        public Task<RecycleBinAdapterResult> RecycleAsync(
            string path,
            FileTreeSnapshot expectedSnapshot,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Directory.CreateDirectory(recycleRoot);
            string destination = Path.Combine(recycleRoot, Guid.NewGuid().ToString("N") + "-" + Path.GetFileName(path));
            if (Directory.Exists(path))
            {
                Directory.Move(path, destination);
            }
            else
            {
                File.Move(path, destination);
            }

            Paths.Add(path);
            return Task.FromResult(new RecycleBinAdapterResult(RecycleBinAdapterState.Recycled));
        }
    }
}
