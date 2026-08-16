namespace BF6CrashDiagnostic.Core.Analysis;

public static class StatusCodeInterpreter
{
    public const string StatusUnsuccessful = "0xC0000001";

    public static string Explain(string? text)
    {
        if (!string.IsNullOrWhiteSpace(text) &&
            text.Contains(StatusUnsuccessful, StringComparison.OrdinalIgnoreCase))
        {
            return "0xC0000001 is STATUS_UNSUCCESSFUL, a generic operation failure. It is not a memory-leak code.";
        }

        return "Unknown status code; no interpretation is available.";
    }
}
