using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class WheaEventDecoderTests
{
    private static readonly DateTimeOffset EventTime = DateTimeOffset.Parse("2026-08-02T04:40:00Z");

    [Fact]
    public void TryDecode_ReturnsCanonicalBoundedFieldsWithoutRawOrMessageData()
    {
        DiagnosticEvent diagnosticEvent = Event(
            18,
            "This rendered message contains FRIEND-PC and must not be copied.",
            new Dictionary<string, string>
            {
                ["ErrorSource"] = "  Machine   Check   Exception  ",
                ["ErrorType"] = "Bus/Interconnect Error",
                ["ApicId"] = "12",
                ["MCABank"] = "0x0a",
                ["MciStat"] = "0xBEA0000000000108",
                ["RawData"] = new string('A', 512),
                ["ErrorRecord"] = new string('B', 512),
                ["DeviceName"] = @"C:\Users\FRIEND\device.txt",
                ["param1"] = "FRIEND-PC"
            });

        bool success = WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? actual);

        Assert.True(success);
        Assert.NotNull(actual);
        Assert.Equal(18, actual.EventId);
        Assert.Equal(WheaEventClassification.Fatal, actual.Classification);
        Assert.Equal("Machine Check Exception", actual.Fields["ErrorSource"]);
        Assert.Equal("Bus/Interconnect Error", actual.Fields["ErrorType"]);
        Assert.Equal("12", actual.Fields["ApicId"]);
        Assert.Equal("0x0A", actual.Fields["MCABank"]);
        Assert.Equal("0xBEA0000000000108", actual.Fields["MciStat"]);
        Assert.DoesNotContain("RawData", actual.Fields.Keys);
        Assert.DoesNotContain("ErrorRecord", actual.Fields.Keys);
        Assert.DoesNotContain("DeviceName", actual.Fields.Keys);
        Assert.DoesNotContain("param1", actual.Fields.Keys);
        Assert.DoesNotContain("FRIEND-PC", string.Join(' ', actual.Fields.Values), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryDecode_RejectsNonWheaProviderEvenWhenNameContainsWhea()
    {
        DiagnosticEvent diagnosticEvent = Event(
            18,
            "A fatal hardware error has occurred.",
            new Dictionary<string, string> { ["ErrorType"] = "Machine Check" },
            providerName: "Example-WHEA-Logger");

        Assert.False(WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? actual));
        Assert.Null(actual);
    }

    [Fact]
    public void TryDecode_RejectsCanonicalNameWithConflictingProviderGuid()
    {
        DiagnosticEvent diagnosticEvent = Event(
            18,
            "A fatal hardware error has occurred.",
            new Dictionary<string, string> { ["ErrorType"] = "Machine Check" },
            providerGuid: Guid.Empty);

        Assert.False(WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? actual));
        Assert.Null(actual);
    }

    [Fact]
    public void TryDecode_KeepsUnknownEventUnclassifiedWithoutMessageGuessing()
    {
        DiagnosticEvent diagnosticEvent = Event(
            999,
            "A fatal uncorrectable hardware error has occurred.",
            new Dictionary<string, string> { ["ErrorType"] = "Machine Check" });

        Assert.True(WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? actual));
        Assert.NotNull(actual);
        Assert.Equal(WheaEventClassification.Unknown, actual.Classification);
    }

    [Fact]
    public void TryDecode_OmitsOversizedBlobLikePrivateAndMalformedValues()
    {
        DiagnosticEvent diagnosticEvent = Event(
            17,
            "A corrected hardware error has occurred.",
            new Dictionary<string, string>
            {
                ["ErrorSource"] = new string('E', 97),
                ["ErrorType"] = "C:/Users/Friend/private.txt",
                ["OperationType"] = "friend@example.invalid",
                ["TransactionType"] = "0123456789ABCDEF0123456789ABCDEF",
                ["ApicId"] = "12 processors",
                ["MCABank"] = "0x1234567890ABCDEF0",
                ["MciStat"] = "184467440737095516150"
            });

        Assert.True(WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? actual));
        Assert.NotNull(actual);
        Assert.Empty(actual.Fields);
        Assert.Equal(WheaEventClassification.Corrected, actual.Classification);
    }

    [Fact]
    public void TryDecode_OmitsCaseVariantFieldWhenValuesConflict()
    {
        DiagnosticEvent diagnosticEvent = Event(
            17,
            "A corrected hardware error has occurred.",
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ErrorType"] = "Cache Error",
                ["errortype"] = "Bus Error"
            });

        Assert.True(WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? actual));
        Assert.NotNull(actual);
        Assert.DoesNotContain("ErrorType", actual.Fields.Keys);
    }

    [Fact]
    public void TryDecode_ReturnsReadOnlyFieldCollection()
    {
        DiagnosticEvent diagnosticEvent = Event(
            17,
            "A corrected hardware error has occurred.",
            new Dictionary<string, string> { ["ErrorType"] = "Cache Error" });

        Assert.True(WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? actual));
        Assert.NotNull(actual);
        IDictionary<string, string> mutableView = Assert.IsAssignableFrom<IDictionary<string, string>>(actual.Fields);
        Assert.Throws<NotSupportedException>(() => mutableView.Add("RawData", "secret"));
    }

    private static DiagnosticEvent Event(
        int eventId,
        string message,
        IReadOnlyDictionary<string, string> data,
        string providerName = WheaEventCatalog.ProviderName,
        Guid? providerGuid = null) =>
        new(
            EventTime,
            "System",
            providerName,
            providerGuid,
            eventId,
            2,
            "Error",
            message,
            data);
}
