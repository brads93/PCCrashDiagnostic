using System.Xml;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class WindowsEventCollectorTests
{
    [Fact]
    public void ParseEventXml_IdentifiesExactProviderTraitsEventAndSubjectProviderGuid()
    {
        string xml = File.ReadAllText(FixturePath("KernelEventTracing-ProviderTraits.xml"));

        DiagnosticEvent actual = WindowsEventCollector.ParseEventXml(xml);

        Assert.Equal(DateTimeOffset.Parse("2026-08-02T04:42:18.1250000Z"), actual.TimeUtc);
        Assert.Equal("Microsoft-Windows-Kernel-EventTracing/Admin", actual.LogName);
        Assert.Equal("Microsoft-Windows-Kernel-EventTracing", actual.ProviderName);
        Assert.Equal(Guid.Parse("8444a4fb-d8d3-4f38-84f8-89960a1ef12f"), actual.ProviderGuid);
        Assert.Equal(28, actual.EventId);
        Assert.Equal((byte)2, actual.Level);
        Assert.Equal("Error", actual.LevelName);
        Assert.Equal(
            "Error setting traits on Provider {8444a4fb-d8d3-4f38-84f8-89960a1ef12f}. Error: 0xC0000001",
            actual.Message);
        Assert.Equal("3221225473", actual.Data["ErrorCode"]);
        Assert.Equal("{8444A4FB-D8D3-4F38-84F8-89960A1EF12F}", actual.Data["ProviderGuid"]);
    }

    [Fact]
    public void ParseEventXml_WhitelistsDataAndDropsComputerCorrelationAndExecution()
    {
        string xml = File.ReadAllText(FixturePath("KernelEventTracing-ProviderTraits.xml"));

        DiagnosticEvent actual = WindowsEventCollector.ParseEventXml(xml);
        string exportedSurface = actual.Message + " " + string.Join(' ', actual.Data.Select(pair => pair.Key + "=" + pair.Value));

        Assert.DoesNotContain("FRIEND-PC", exportedSurface, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("example.invalid", exportedSurface, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", exportedSurface, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ProcessID", actual.Data.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("ThreadID", actual.Data.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(2, actual.Data.Count);
    }

    [Fact]
    public void ParseEventXml_ProhibitsDtdExpansion()
    {
        const string xml = "<!DOCTYPE Event [<!ENTITY secret SYSTEM 'file:///C:/Windows/win.ini'>]>" +
                           "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
                           "<System><Provider Name='Example'/><EventID>1</EventID><Level>2</Level>" +
                           "<TimeCreated SystemTime='2026-08-02T04:42:00Z'/><Channel>System</Channel></System>" +
                           "<EventData><Data Name='param1'>&secret;</Data></EventData></Event>";

        Assert.Throws<XmlException>(() => WindowsEventCollector.ParseEventXml(xml));
    }

    [Theory]
    [InlineData("disk", "EventID=7 or EventID=11 or EventID=51 or EventID=153")]
    [InlineData("storahci", "EventID=129")]
    [InlineData("stornvme", "EventID=129")]
    [InlineData("Microsoft-Windows-StorPort", "EventID=129")]
    [InlineData("Ntfs", "EventID=50 or EventID=55 or EventID=98 or EventID=140")]
    [InlineData("Microsoft-Windows-Ntfs", "EventID=50 or EventID=55 or EventID=98 or EventID=140")]
    [InlineData("ReFS", "EventID=134")]
    [InlineData("Microsoft-Windows-ReFS", "EventID=134")]
    [InlineData("volmgr", "EventID=46 or EventID=161")]
    [InlineData("Microsoft-Windows-MemoryDiagnostics-Results", "EventID=1101 or EventID=1102 or EventID=1103 or EventID=1104 or EventID=1201 or EventID=1202")]
    public void EvidenceSystemXPath_UsesOneExplicitEventIdClauseForEachBoundedProvider(
        string provider,
        string eventIds)
    {
        string xpath = WindowsEventCollector.BuildEvidenceSystemXPath(
            DateTimeOffset.Parse("2026-08-01T00:00:00Z"),
            DateTimeOffset.Parse("2026-08-02T00:00:00Z"));
        string providerPredicate = $"Provider[@Name='{provider}']";

        Assert.Contains($"({providerPredicate} and ({eventIds}))", xpath, StringComparison.Ordinal);
        Assert.Single(Regex.Matches(xpath, Regex.Escape(providerPredicate)).Cast<Match>());
    }

    [Fact]
    public void EvidenceSystemXPath_DoesNotCollectUnrelatedStorageOrMemoryDiagnosticEvents()
    {
        string xpath = WindowsEventCollector.BuildEvidenceSystemXPath(
            DateTimeOffset.Parse("2026-08-01T00:00:00Z"),
            DateTimeOffset.Parse("2026-08-02T00:00:00Z"));

        Assert.DoesNotContain("MemoryDiagnostics-Schedule", xpath, StringComparison.Ordinal);
        Assert.DoesNotContain("Microsoft-Windows-StorageSpaces-Driver", xpath, StringComparison.Ordinal);
    }

    [Fact]
    public void ParseEventXml_MemoryDiagnosticResultKeepsCompletionAndDropsDeviceIdentity()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
              <System>
                <Provider Name='Microsoft-Windows-MemoryDiagnostics-Results' Guid='{5f92bc59-248f-4111-86a9-e393e12c6139}' />
                <EventID>1202</EventID>
                <Level>2</Level>
                <TimeCreated SystemTime='2026-08-02T04:42:00Z' />
                <Channel>System</Channel>
                <Computer>PRIVATE-PC-NAME</Computer>
              </System>
              <UserData>
                <Results xmlns='http://manifests.microsoft.com/win/2005/08/windows/Reliability/Postboot/Events'>
                  <CompletionType>Fail</CompletionType>
                  <SerialNumber>PRIVATE-DEVICE-SERIAL</SerialNumber>
                </Results>
              </UserData>
            </Event>
            """;

        DiagnosticEvent actual = WindowsEventCollector.ParseEventXml(xml);
        string exportedSurface = actual.Message + " " +
            string.Join(' ', actual.Data.Select(pair => pair.Key + "=" + pair.Value));

        Assert.Equal("Fail", actual.Data["CompletionType"]);
        Assert.DoesNotContain("SerialNumber", actual.Data.Keys, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE-DEVICE-SERIAL", exportedSurface, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE-PC-NAME", exportedSurface, StringComparison.OrdinalIgnoreCase);
    }

    private static string FixturePath(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
}
