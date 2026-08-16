using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

public sealed class ReportWriterTests
{
    [Fact]
    public async Task WriteAsync_CreatesSchema2ReportManifestZipAndMatchingChecksum()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        DiagnosticReport report = CreateReport("schema-and-hash");

        ReportPackage package = await writer.WriteAsync(report, CancellationToken.None);

        Assert.True(File.Exists(package.ZipPath));
        Assert.StartsWith("BF6-Diagnostic-Report-", Path.GetFileName(package.ZipPath), StringComparison.Ordinal);
        Assert.True(File.Exists(package.Sha256Path));
        Assert.False(File.Exists(package.ZipPath + ".partial"));
        Assert.False(File.Exists(package.Sha256Path + ".partial"));
        Assert.Equal(await ComputeSha256Async(package.ZipPath), package.Sha256);
        Assert.Equal(
            $"{package.Sha256} *{Path.GetFileName(package.ZipPath)}{Environment.NewLine}",
            await File.ReadAllTextAsync(package.Sha256Path, CancellationToken.None));

        using ZipArchive archive = ZipFile.OpenRead(package.ZipPath);
        string[] expectedEntries =
        [
            "SUMMARY.txt",
            "Report.json",
            "Performance-Samples.csv",
            "Windows-Events.json",
            "Windows-Event-Groups.json",
            "Reliability.json",
            "Artifacts.json",
            "Collection-Status.json",
            "Manifest.json"
        ];
        Assert.Equal(expectedEntries.Order(), archive.Entries.Select(entry => entry.FullName).Order());

        ZipArchiveEntry reportEntry = Assert.Single(archive.Entries, entry => entry.FullName == "Report.json");
        await using (Stream reportStream = reportEntry.Open())
        using (JsonDocument reportJson = await JsonDocument.ParseAsync(reportStream, cancellationToken: CancellationToken.None))
        {
            Assert.Equal(2, reportJson.RootElement.GetProperty("ReportSchemaVersion").GetInt32());
            Assert.Equal("schema-and-hash", reportJson.RootElement.GetProperty("SessionId").GetString());
        }

        ZipArchiveEntry manifestEntry = Assert.Single(archive.Entries, entry => entry.FullName == "Manifest.json");
        await using Stream manifestStream = manifestEntry.Open();
        using JsonDocument manifest = await JsonDocument.ParseAsync(manifestStream, cancellationToken: CancellationToken.None);
        Assert.Equal(2, manifest.RootElement.GetProperty("ReportSchemaVersion").GetInt32());
        Assert.Equal("schema-and-hash", manifest.RootElement.GetProperty("SessionId").GetString());
        Assert.Equal(8, manifest.RootElement.GetProperty("Files").GetArrayLength());
        foreach (JsonElement fileEntry in manifest.RootElement.GetProperty("Files").EnumerateArray())
        {
            string name = Assert.IsType<string>(fileEntry.GetProperty("Name").GetString());
            string filePath = Path.Combine(package.SessionFolder, name);
            Assert.True(File.Exists(filePath), $"Manifest member is missing: {name}");
            Assert.Equal(new FileInfo(filePath).Length, fileEntry.GetProperty("SizeBytes").GetInt64());
            Assert.Equal(
                await ComputeSha256Async(filePath),
                fileEntry.GetProperty("Sha256").GetString());
        }
    }

    [Fact]
    public async Task WriteAsync_QuotesSpreadsheetFormulaLikeCsvValues()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        DiagnosticReport report = CreateReport("csv-injection") with
        {
            Samples =
            [
                CreateSample("=HYPERLINK(\"https://example.invalid\")")
            ]
        };

        ReportPackage package = await writer.WriteAsync(report, CancellationToken.None);

        string csv = await File.ReadAllTextAsync(
            Path.Combine(package.SessionFolder, "Performance-Samples.csv"),
            CancellationToken.None);
        Assert.Contains("\"'=HYPERLINK(\"\"https://example.invalid\"\")\"", csv, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WriteAsync_PackagesOnlyTheExactReportMemberAllowlist()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        DiagnosticReport report = CreateReport("exact-members");
        string sessionFolder = Path.Combine(writer.SessionsRoot, report.SessionId);
        Directory.CreateDirectory(sessionFolder);
        await File.WriteAllTextAsync(Path.Combine(sessionFolder, "unexpected-secret.txt"), "must not ship");
        await File.WriteAllTextAsync(Path.Combine(sessionFolder, "ACTIVE.json"), "{}");
        await File.WriteAllTextAsync(Path.Combine(sessionFolder, "samples.journal.jsonl"), "{}");

        ReportPackage package = await writer.WriteAsync(report, CancellationToken.None);

        using ZipArchive archive = ZipFile.OpenRead(package.ZipPath);
        Assert.DoesNotContain(archive.Entries, entry => entry.FullName == "unexpected-secret.txt");
        Assert.DoesNotContain(archive.Entries, entry => entry.FullName == "ACTIVE.json");
        Assert.DoesNotContain(archive.Entries, entry => entry.FullName.EndsWith(".journal.jsonl", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("../escape")]
    [InlineData("folder\\escape")]
    [InlineData("CON")]
    [InlineData("NUL.txt")]
    [InlineData("trailing.")]
    [InlineData("trailing ")]
    public async Task WriteAsync_RejectsUnsafeSessionIds(string sessionId)
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            writer.WriteAsync(CreateReport(sessionId), CancellationToken.None));
    }

    [Fact]
    public async Task WriteAsync_RejectsOverlongSessionId()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            writer.WriteAsync(CreateReport(new string('a', 129)), CancellationToken.None));
    }

    [Fact]
    public async Task WriteAsync_DoesNotOverwriteAnExistingPackage()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        DiagnosticReport report = CreateReport("unique-package");

        ReportPackage first = await writer.WriteAsync(report, CancellationToken.None);
        ReportPackage second = await writer.WriteAsync(report, CancellationToken.None);

        Assert.NotEqual(first.ZipPath, second.ZipPath);
        Assert.True(File.Exists(first.ZipPath));
        Assert.True(File.Exists(first.Sha256Path));
        Assert.True(File.Exists(second.ZipPath));
        Assert.True(File.Exists(second.Sha256Path));
        Assert.Equal(await ComputeSha256Async(first.ZipPath), first.Sha256);
        Assert.Equal(await ComputeSha256Async(second.ZipPath), second.Sha256);
    }

    [Fact]
    public async Task WriteAsync_RejectsPlantedReportMemberReparseLink()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        DiagnosticReport report = CreateReport("planted-member-link");
        string sessionFolder = Path.Combine(writer.SessionsRoot, report.SessionId);
        Directory.CreateDirectory(sessionFolder);
        string outsideSentinel = Path.Combine(directory.Path, "outside-sentinel.txt");
        await File.WriteAllTextAsync(outsideSentinel, "unchanged", CancellationToken.None);
        string plantedMember = Path.Combine(sessionFolder, "SUMMARY.txt");
        if (!TryCreateFileSymbolicLink(plantedMember, outsideSentinel))
        {
            return;
        }

        await Assert.ThrowsAsync<IOException>(() => writer.WriteAsync(report, CancellationToken.None));

        Assert.Equal("unchanged", await File.ReadAllTextAsync(outsideSentinel, CancellationToken.None));
        Assert.False(Directory.Exists(writer.ReportsRoot) &&
                     Directory.EnumerateFiles(writer.ReportsRoot, "*.zip", SearchOption.TopDirectoryOnly).Any());
    }

    [Fact]
    public async Task WriteAsync_UsesFreshRandomCreateNewTempsInsteadOfPredictableMemberName()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        DiagnosticReport report = CreateReport("random-member-temp");
        string sessionFolder = Path.Combine(writer.SessionsRoot, report.SessionId);
        Directory.CreateDirectory(sessionFolder);
        string plantedPredictableTemp = Path.Combine(sessionFolder, "SUMMARY.txt.partial");
        await File.WriteAllTextAsync(plantedPredictableTemp, "planted", CancellationToken.None);

        ReportPackage package = await writer.WriteAsync(report, CancellationToken.None);

        Assert.Equal("planted", await File.ReadAllTextAsync(plantedPredictableTemp, CancellationToken.None));
        Assert.True(File.Exists(package.ZipPath));
        Assert.Empty(Directory.EnumerateFiles(sessionFolder, ".*.partial", SearchOption.TopDirectoryOnly));
    }

    private static DiagnosticReport CreateReport(string sessionId) =>
        new(
            2,
            "2.0.0-beta.1",
            sessionId,
            DiagnosticMode.Retrospective,
            DateTimeOffset.Parse("2026-08-02T04:40:00Z"),
            DateTimeOffset.Parse("2026-08-02T04:50:00Z"),
            "Completed",
            null,
            null,
            null,
            [CreateSample("BF6")],
            [],
            [],
            [],
            [],
            [],
            [new CollectionStatus("Synthetic", CollectionState.Available, "Fixture")],
            "Synthetic summary." + Environment.NewLine);

    private static PerformanceSample CreateSample(string processName) =>
        new(
            DateTimeOffset.Parse("2026-08-02T04:42:00Z"),
            true,
            1234,
            processName,
            50,
            16,
            16,
            24,
            40,
            60,
            5000,
            4000,
            40,
            75,
            80,
            9000,
            500,
            20);

    private static async Task<string> ComputeSha256Async(string path)
    {
        await using FileStream stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
    }

    private static bool TryCreateFileSymbolicLink(string linkPath, string targetPath)
    {
        try
        {
            File.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }
}
