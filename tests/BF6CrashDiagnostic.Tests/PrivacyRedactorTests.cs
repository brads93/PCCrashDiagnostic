using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class PrivacyRedactorTests
{
    [Fact]
    public void Redact_RemovesCommonPersonalIdentifiersAndArbitraryGuid()
    {
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");
        const string input = "Brad on FRIEND-PC/EXAMPLE C:\\Users\\Brad\\Desktop sent brad@example.com " +
                             "from 192.168.1.42, fe80::1234:5678:90ab:cdef and AA-BB-CC-DD-EE-FF " +
                             "as S-1-5-21-111111111-222222222-333333333-1001 " +
                             "activity aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.";

        string actual = redactor.Redact(input);

        Assert.DoesNotContain("Brad", actual, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("FRIEND-PC", actual, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("EXAMPLE", actual, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.168.1.42", actual, StringComparison.Ordinal);
        Assert.DoesNotContain("AA-BB-CC-DD-EE-FF", actual, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("S-1-5-21", actual, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", actual, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED-PROFILE]", actual, StringComparison.Ordinal);
        Assert.Contains("[REDACTED-EMAIL]", actual, StringComparison.Ordinal);
        Assert.Contains("[REDACTED-GUID]", actual, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactEvent_PreservesDedicatedProviderGuid_AndRedactsMessageGuid()
    {
        Guid providerGuid = Guid.Parse("8444a4fb-d8d3-4f38-84f8-89960a1ef12f");
        var input = new DiagnosticEvent(
            DateTimeOffset.Parse("2026-08-02T04:42:18.125Z"),
            "Microsoft-Windows-Kernel-EventTracing/Admin",
            "Microsoft-Windows-Kernel-EventTracing",
            providerGuid,
            28,
            2,
            "Error",
            "Error setting traits on Provider {8444a4fb-d8d3-4f38-84f8-89960a1ef12f}. Error: 0xC0000001",
            new Dictionary<string, string>
            {
                ["ActivityId"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            });

        DiagnosticEvent actual = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad")
            .RedactEvent(input);

        Assert.Equal(providerGuid, actual.ProviderGuid);
        Assert.DoesNotContain(providerGuid.ToString(), actual.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED-GUID]", actual.Message, StringComparison.Ordinal);
        Assert.Equal("[REDACTED-GUID]", actual.Data["ActivityId"]);
    }

    [Fact]
    public void RedactGroupAndFinding_RemoveFreeTextIdentifiers_WhileKeepingDedicatedProviderGuid()
    {
        Guid providerGuid = Guid.Parse("8444a4fb-d8d3-4f38-84f8-89960a1ef12f");
        DateTimeOffset time = DateTimeOffset.Parse("2026-08-02T04:42:18Z");
        var group = new DuplicateEventGroup(
            "stable-key",
            "Microsoft-Windows-Kernel-EventTracing",
            providerGuid,
            28,
            @"Brad at C:\Users\Brad; brad@example.com; activity aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            2,
            time,
            time.AddMinutes(1),
            [time, time.AddMinutes(1)]);
        var finding = new DiagnosticFinding(
            "fixture",
            80,
            FindingSeverity.Context,
            FindingConfidence.Low,
            "FRIEND-PC",
            "Provider context for Brad",
            "brad@example.com used provider 8444a4fb-d8d3-4f38-84f8-89960a1ef12f",
            @"See C:\Users\Brad\Desktop",
            "Does not prove S-1-5-21-111111111-222222222-333333333-1001 caused it",
            "Contact Brad");
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");

        DuplicateEventGroup safeGroup = redactor.RedactGroup(group);
        DiagnosticFinding safeFinding = redactor.RedactFinding(finding);

        Assert.Equal(providerGuid, safeGroup.ProviderGuid);
        Assert.NotEqual(group.Key, safeGroup.Key);
        Assert.Contains("[REDACTED-GUID]", safeGroup.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("Brad", safeGroup.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("example.com", safeGroup.Message, StringComparison.OrdinalIgnoreCase);
        string findingText = string.Join(
            ' ',
            safeFinding.Category,
            safeFinding.Title,
            safeFinding.Evidence,
            safeFinding.Meaning,
            safeFinding.DoesNotProve,
            safeFinding.NextCheck);
        Assert.DoesNotContain("Brad", findingText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("FRIEND-PC", findingText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("example.com", findingText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("S-1-5-21", findingText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(providerGuid.ToString(), findingText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED-GUID]", findingText, StringComparison.Ordinal);
    }

    [Fact]
    public void RedactGroup_DerivesStableKeyOnlyFromRedactedFields()
    {
        Guid providerGuid = Guid.Parse("8444a4fb-d8d3-4f38-84f8-89960a1ef12f");
        DateTimeOffset time = DateTimeOffset.Parse("2026-08-02T04:42:18Z");
        var first = new DuplicateEventGroup(
            new string('a', 64),
            "Provider",
            providerGuid,
            28,
            "Brad connected from 192.168.1.42",
            1,
            time,
            time,
            [time]);
        DuplicateEventGroup second = first with
        {
            Key = new string('b', 64),
            Message = "Brad connected from 10.0.0.8"
        };
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");

        DuplicateEventGroup safeFirst = redactor.RedactGroup(first);
        DuplicateEventGroup safeSecond = redactor.RedactGroup(second);

        Assert.Equal("[REDACTED-USER] connected from [REDACTED-IP]", safeFirst.Message);
        Assert.Equal(safeFirst.Message, safeSecond.Message);
        Assert.NotEqual(first.Key, safeFirst.Key);
        Assert.NotEqual(second.Key, safeSecond.Key);
        Assert.Equal(safeFirst.Key, safeSecond.Key);
        Assert.Equal(64, safeFirst.Key.Length);
        Assert.All(safeFirst.Key, character => Assert.True(Uri.IsHexDigit(character)));
    }

    [Fact]
    public void Redact_RedactsShortKnownIdentifiersAtTokenBoundariesWithoutChangingSubstrings()
    {
        var redactor = new PrivacyRedactor("Al", "PC", "AD", @"C:\Users\Al");

        string actual = redactor.Redact(@"Al logged on to \\PC\share in AD. Alice uses UPCYCLE, SHADOW, and PAL.");

        Assert.Equal(
            @"[REDACTED-USER] logged on to \\[REDACTED-COMPUTER]\share in [REDACTED-DOMAIN]. Alice uses UPCYCLE, SHADOW, and PAL.",
            actual);
    }

    [Fact]
    public void Redact_RedactsSingleCharacterKnownIdentifiersOnlyAsTokens()
    {
        var redactor = new PrivacyRedactor("A", "B", "C", @"C:\Users\A");

        string actual = redactor.Redact("A on B in C; ALPHA, BETA, SCAN, and A\u0301 remain.");

        Assert.Equal(
            "[REDACTED-USER] on [REDACTED-COMPUTER] in [REDACTED-DOMAIN]; ALPHA, BETA, SCAN, and A\u0301 remain.",
            actual);
    }

    [Fact]
    public void RedactArtifact_RemovesOriginalPathAndPersonalDataFromMetadata()
    {
        var artifact = new CrashArtifact(
            "Dump belonging to Brad",
            "BF6-Brad.dmp",
            @"C:\Users\Brad\AppData\Local\CrashDumps\BF6-Brad.dmp",
            1234,
            DateTimeOffset.Parse("2026-08-02T04:42:18Z"),
            true,
            @"C:\Users\Brad\AppData\Local\CrashDumps\BF6-Brad.dmp");
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");

        CrashArtifact actual = redactor.RedactArtifact(artifact);

        Assert.Null(actual.OriginalPath);
        Assert.DoesNotContain("Brad", actual.Kind, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Brad", actual.Name, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Brad", actual.RedactedPath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("[REDACTED-PROFILE]", actual.RedactedPath, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_RedactsIpv4ShapedTokenEvenWhenLabeledAsVersion()
    {
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");

        string actual = redactor.Redact("version: 2.0.0.0 contacted 192.168.1.42");

        Assert.DoesNotContain("2.0.0.0", actual, StringComparison.Ordinal);
        Assert.DoesNotContain("192.168.1.42", actual, StringComparison.Ordinal);
        Assert.Equal(2, actual.Split("[REDACTED-IP]", StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public void Redact_DoesNotTreatDistantVersionWordAsIpContext()
    {
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");

        string actual = redactor.Redact("version check contacted 192.168.1.42");

        Assert.DoesNotContain("192.168.1.42", actual, StringComparison.Ordinal);
        Assert.Contains("[REDACTED-IP]", actual, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_PreservesVersionThatCannotBeAnIpv4Address()
    {
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");

        string actual = redactor.Redact("driver version: 31.0.24033.1003");

        Assert.Contains("31.0.24033.1003", actual, StringComparison.Ordinal);
    }
}
