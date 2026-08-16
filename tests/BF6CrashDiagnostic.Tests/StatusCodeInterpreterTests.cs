using BF6CrashDiagnostic.Core.Analysis;

namespace BF6CrashDiagnostic.Tests;

public sealed class StatusCodeInterpreterTests
{
    [Fact]
    public void StatusUnsuccessful_IsExplainedAsGenericFailure_NotMemoryLeak()
    {
        string explanation = StatusCodeInterpreter.Explain(
            "Error setting traits on Provider {8444a4fb-d8d3-4f38-84f8-89960a1ef12f}. Error: 0xC0000001");

        Assert.Contains("STATUS_UNSUCCESSFUL", explanation, StringComparison.Ordinal);
        Assert.Contains("generic operation failure", explanation, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not a memory-leak code", explanation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void UnknownStatus_DoesNotInventCause()
    {
        string explanation = StatusCodeInterpreter.Explain("Error: 0xDEADBEEF");

        Assert.Contains("no interpretation is available", explanation, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("memory leak", explanation, StringComparison.OrdinalIgnoreCase);
    }
}
