using System.IO;

namespace BF6CrashDiagnostic.App;

internal sealed record CommandLineOptions(
    string DataRoot,
    bool SmokeTest,
    bool VerifyHelperBinding)
{
    public static CommandLineOptions Parse(IReadOnlyList<string> arguments)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string defaultRoot = Path.Combine(localAppData, "PCCrashDiagnostic");

        string dataRoot = defaultRoot;
        bool dataRootSeen = false;
        bool smokeTest = false;
        bool verifyHelperBinding = false;

        for (int index = 0; index < arguments.Count; index++)
        {
            string argument = arguments[index];
            if (string.Equals(argument, "--smoke-test", StringComparison.OrdinalIgnoreCase))
            {
                if (smokeTest)
                {
                    throw new ArgumentException("--smoke-test may only be specified once.");
                }

                smokeTest = true;
                continue;
            }

            if (string.Equals(argument, "--verify-helper-binding", StringComparison.OrdinalIgnoreCase))
            {
                if (verifyHelperBinding)
                {
                    throw new ArgumentException("--verify-helper-binding may only be specified once.");
                }

                verifyHelperBinding = true;
                continue;
            }

            if (string.Equals(argument, "--data-root", StringComparison.OrdinalIgnoreCase))
            {
                if (dataRootSeen || index + 1 >= arguments.Count || string.IsNullOrWhiteSpace(arguments[index + 1]))
                {
                    throw new ArgumentException("--data-root requires one absolute folder path.");
                }

                string expanded = Environment.ExpandEnvironmentVariables(arguments[++index]);
                if (!Path.IsPathFullyQualified(expanded))
                {
                    throw new ArgumentException("--data-root must be an absolute folder path.");
                }

                dataRoot = Path.GetFullPath(expanded);
                dataRootSeen = true;
                continue;
            }

            throw new ArgumentException($"Unknown option: {argument}\n\nUsage: PCCrashDiagnostic.exe [--data-root <absolute-folder-path>] [--smoke-test | --verify-helper-binding]");
        }

        if (verifyHelperBinding && (smokeTest || dataRootSeen))
        {
            throw new ArgumentException("--verify-helper-binding must be used by itself.");
        }

        return new CommandLineOptions(dataRoot, smokeTest, verifyHelperBinding);
    }
}
