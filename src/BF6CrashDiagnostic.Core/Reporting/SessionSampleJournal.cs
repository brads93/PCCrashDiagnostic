using System.Text;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed class SessionSampleJournal
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);
    private static readonly JsonSerializerOptions JsonOptions = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public string GetPath(string sessionFolder) => Path.Combine(sessionFolder, "Performance-Samples.journal.jsonl");

    public async Task AppendAsync(string sessionFolder, PerformanceSample sample, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(sessionFolder);
        string line = JsonSerializer.Serialize(sample, JsonOptions) + "\n";
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(GetPath(sessionFolder), line, Utf8NoBom, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<PerformanceSample>> ReadAsync(string sessionFolder, CancellationToken cancellationToken = default)
    {
        string path = GetPath(sessionFolder);
        if (!File.Exists(path))
        {
            return [];
        }

        var samples = new List<PerformanceSample>();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024, useAsync: true);
            using var reader = new StreamReader(stream, Utf8NoBom, detectEncodingFromByteOrderMarks: true);
            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    PerformanceSample? sample = JsonSerializer.Deserialize<PerformanceSample>(line, JsonOptions);
                    if (sample is not null)
                    {
                        samples.Add(sample);
                    }
                }
                catch (JsonException)
                {
                    // A final partially flushed line is ignored; earlier complete samples remain usable.
                }
            }
        }
        finally
        {
            _gate.Release();
        }

        return samples.OrderBy(sample => sample.TimestampUtc).ToArray();
    }
}
