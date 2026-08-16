namespace BF6CrashDiagnostic.Tests;

internal sealed class TestDirectory : IDisposable
{
    public TestDirectory()
    {
        Path = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(),
            "BF6CrashDiagnostic.Tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        if (!Directory.Exists(Path))
        {
            return;
        }

        string fullPath = System.IO.Path.GetFullPath(Path);
        string expectedRoot = System.IO.Path.GetFullPath(
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "BF6CrashDiagnostic.Tests"));
        if (!fullPath.StartsWith(expectedRoot + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Refusing to delete a test directory outside the dedicated test root.");
        }

        Directory.Delete(fullPath, recursive: true);
    }
}

