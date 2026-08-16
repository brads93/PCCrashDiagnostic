using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using BF6CrashDiagnostic.Core.Sharing;

namespace BF6CrashDiagnostic.Tests;

public sealed class TechnicalReportExportValidatorTests
{
    [Fact]
    public async Task PrepareAndExport_AcceptValidatedSchemaTwoArchiveWithoutRewritingSource()
    {
        using var directory = new TestDirectory();
        DateTimeOffset now = new(2026, 8, 16, 12, 0, 0, TimeSpan.Zero);
        var legacy = new DiagnosticReport(
            2,
            "2.0.0-beta.1",
            "technical-schema-two",
            DiagnosticMode.Retrospective,
            now,
            now.AddMinutes(1),
            "Completed",
            new CrashAnchor(now, "Microsoft-Windows-WER-SystemErrorReporting", 1001, "Blue screen", "0x116"),
            null,
            null,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            "Legacy report");
        ReportPackage package = await new ReportWriter(directory.Path).WriteAsync(legacy);
        byte[] original = await File.ReadAllBytesAsync(package.ZipPath);
        var registry = new ReportHandleRegistry(directory.Path);
        UiReportHandle handle = await registry.RegisterValidatedAsync(ReportOrigin.Generated, [package.ZipPath]);
        var validator = new TechnicalReportExportValidator(registry);

        TechnicalReportExportTicket ticket = await validator.PrepareAsync(handle);
        string destination = Path.Combine(directory.Path, "schema-two-export.zip");
        await validator.ExportAsync(ticket.Ticket, destination);

        ValidatedReportArchive exported = await IncidentLibrary.ReadValidatedArchiveAsync(destination);
        Assert.Equal(2, exported.ReportSchemaVersion);
        Assert.Equal("technical-schema-two", exported.SessionId);
        Assert.Equal(original, await File.ReadAllBytesAsync(package.ZipPath));
    }

    [Fact]
    public async Task PrepareAndExport_RequireValidatedHandleBoundSchemaThreeArchive()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        ReportPackageV3 package = await writer.WriteV3Async(SafeSummaryTestData.Create("technical-session"));
        var registry = new ReportHandleRegistry(directory.Path);
        UiReportHandle handle = await registry.RegisterValidatedAsync(ReportOrigin.Generated, [package.ZipPath]);
        var validator = new TechnicalReportExportValidator(registry);
        TechnicalReportExportTicket ticket = await validator.PrepareAsync(handle);
        string destination = Path.Combine(directory.Path, ticket.SuggestedFileName);

        TechnicalReportExportResult result = await validator.ExportAsync(ticket.Ticket, destination);

        Assert.True(File.Exists(destination));
        Assert.Equal(new FileInfo(destination).Length, result.BytesWritten);
        Assert.DoesNotContain(directory.Path, result.Destination.Warning, StringComparison.OrdinalIgnoreCase);
        ValidatedReportArchive validated = await IncidentLibrary.ReadValidatedArchiveAsync(destination);
        Assert.Equal(3, validated.ReportSchemaVersion);
        Assert.Equal("technical-session", validated.SessionId);
    }

    [Fact]
    public async Task Export_RejectsSourceChangedAfterTicket()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        ReportPackageV3 package = await writer.WriteV3Async(SafeSummaryTestData.Create("technical-tamper"));
        var registry = new ReportHandleRegistry(directory.Path);
        UiReportHandle handle = await registry.RegisterValidatedAsync(ReportOrigin.Generated, [package.ZipPath]);
        var validator = new TechnicalReportExportValidator(registry);
        TechnicalReportExportTicket ticket = await validator.PrepareAsync(handle);
        await File.AppendAllTextAsync(package.ZipPath, "changed");

        await Assert.ThrowsAnyAsync<Exception>(() => validator.ExportAsync(
            ticket.Ticket,
            Path.Combine(directory.Path, "not-created.zip")));
        Assert.False(File.Exists(Path.Combine(directory.Path, "not-created.zip")));
    }

    [Fact]
    public async Task Export_RejectsDestinationDirectoryReplacementBeforeWritingAnyReportBytes()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        ReportPackageV3 package = await writer.WriteV3Async(SafeSummaryTestData.Create("technical-destination-race"));
        var registry = new ReportHandleRegistry(directory.Path);
        UiReportHandle handle = await registry.RegisterValidatedAsync(ReportOrigin.Generated, [package.ZipPath]);
        string exportDirectory = Path.Combine(directory.Path, "chosen-export-folder");
        string movedDirectory = Path.Combine(directory.Path, "original-export-folder");
        Directory.CreateDirectory(exportDirectory);
        var validator = new TechnicalReportExportValidator(
            registry,
            timeProvider: null,
            beforeDestinationLeaseAcquisition: () =>
            {
                Directory.Move(exportDirectory, movedDirectory);
                Directory.CreateDirectory(exportDirectory);
            });
        TechnicalReportExportTicket ticket = await validator.PrepareAsync(handle);
        string destination = Path.Combine(exportDirectory, "technical-report.zip");

        await Assert.ThrowsAsync<IOException>(() => validator.ExportAsync(ticket.Ticket, destination));

        Assert.Empty(Directory.EnumerateFiles(exportDirectory));
        Assert.Empty(Directory.EnumerateFiles(movedDirectory));
        Assert.False(File.Exists(destination));
    }

    [Fact]
    public async Task Export_RejectsSameIdentityContentSubstitutionUsingInternalArchiveHash()
    {
        using var targetData = new TestDirectory();
        using var replacementData = new TestDirectory();
        const string sessionId = "technical-same-identity";
        DiagnosticReportV3 original = SafeSummaryTestData.Create(sessionId);
        DiagnosticReportV3 changed = original with
        {
            Bugchecks =
            [
                original.Bugchecks[0] with
                {
                    Code = 0x117,
                    NormalizedCode = "0x00000117",
                    BugcheckName = "VIDEO_TDR_TIMEOUT_DETECTED"
                }
            ]
        };
        ReportPackageV3 target = await new ReportWriter(targetData.Path).WriteV3Async(original);
        ReportPackageV3 replacement = await new ReportWriter(replacementData.Path).WriteV3Async(changed);
        SafeSummaryTestData.SameIdentityArchiveSubstitution substitution =
            await SafeSummaryTestData.PrepareSameIdentitySubstitutionAsync(target.ZipPath, replacement.ZipPath);
        var registry = new ReportHandleRegistry(targetData.Path);
        UiReportHandle handle = await registry.RegisterValidatedAsync(ReportOrigin.Generated, [target.ZipPath]);
        var validator = new TechnicalReportExportValidator(registry);
        TechnicalReportExportTicket ticket = await validator.PrepareAsync(handle);

        await SafeSummaryTestData.ApplySameIdentitySubstitutionAsync(target.ZipPath, substitution);

        Assert.True(registry.IsValid(handle));
        string destination = Path.Combine(targetData.Path, "must-not-publish.zip");
        InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            validator.ExportAsync(ticket.Ticket, destination));
        Assert.Contains("changed", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(destination));
    }
}
