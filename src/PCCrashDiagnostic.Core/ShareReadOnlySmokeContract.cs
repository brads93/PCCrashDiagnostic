using System.Text.Json;
using PCCrashDiagnostic.Contracts;

namespace PCCrashDiagnostic.Core;

public static class ShareReadOnlySmokeContract
{
    public static int Run(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        try
        {
            if (args.Count != 3 ||
                !string.Equals(args[0], "--smoke-test", StringComparison.Ordinal) ||
                !string.Equals(args[1], "--data-root", StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(args[2]) ||
                !Path.IsPathFullyQualified(args[2]))
            {
                return 2;
            }

            string root = Path.GetFullPath(args[2]);
            Directory.CreateDirectory(root);
            string destination = Path.Combine(root, "smoke-test.json");
            if (File.Exists(destination) || Directory.Exists(destination))
            {
                return 3;
            }

            var marker = new
            {
                Status = "passed",
                ToolVersion = BuildProfile.Version,
                FeatureProfile = BuildProfile.Current.Profile.ToString(),
                PrivilegedOperationsEnabled = BuildProfile.Current.HasAnyPrivilegedCapability,
                RuntimeVersion = Environment.Version.ToString()
            };
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(
                marker,
                new JsonSerializerOptions { WriteIndented = true });
            string temporary = Path.Combine(root, ".pcd-smoke-" + Guid.NewGuid().ToString("N") + ".partial");
            try
            {
                using (var output = new FileStream(
                           temporary,
                           FileMode.CreateNew,
                           FileAccess.Write,
                           FileShare.None,
                           4096,
                           FileOptions.WriteThrough))
                {
                    output.Write(json);
                    output.Flush(flushToDisk: true);
                }

                File.Move(temporary, destination);
            }
            finally
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }

            return 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return 1;
        }
    }
}
