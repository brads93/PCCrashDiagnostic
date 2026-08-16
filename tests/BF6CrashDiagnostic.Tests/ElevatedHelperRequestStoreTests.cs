using System.Text.Json;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class ElevatedHelperRequestStoreTests
{
    [Fact]
    public void ResolveOrigin_ValidatesAllPathComponentsBeforeExistenceProbe()
    {
        using var directory = new TestDirectory();
        string sid = (System.Security.Principal.WindowsIdentity.GetCurrent().User ??
                      throw new InvalidOperationException("The test user SID was unavailable.")).Value;
        bool validated = false;
        bool probed = false;

        Assert.Throws<InvalidDataException>(() =>
            ElevatedHelperRequestStore.ResolveOriginFromCandidates(
                new string('a', 32),
                [new ElevatedHelperOriginCandidate(sid, directory.Path)],
                (localRoot, requestPath) =>
                {
                    Assert.StartsWith(Path.GetFullPath(localRoot), requestPath, StringComparison.OrdinalIgnoreCase);
                    validated = true;
                },
                _ =>
                {
                    Assert.True(validated);
                    probed = true;
                    return false;
                }));

        Assert.True(validated);
        Assert.True(probed);
    }

    [Fact]
    public async Task TryReadResponseAsync_ResponseStillBeingWritten_IsNotConsumedOrDeleted()
    {
        using var directory = new TestDirectory();
        var store = new ElevatedHelperRequestStore(directory.Path);
        ElevatedHelperTicket ticket = await store.CreateRequestAsync(
            new ProtectedEvidenceRequest(
                ProtectedEvidenceOperation.RetryNamedSource,
                ProtectedEvidenceSource.SystemEventLog,
                null,
                null,
                null,
                false,
                false,
                false),
            CancellationToken.None);

        await using (var writer = new FileStream(
                         ticket.ResponsePath,
                         FileMode.CreateNew,
                         FileAccess.Write,
                         FileShare.None,
                         4096,
                         FileOptions.Asynchronous))
        {
            await writer.WriteAsync("{"u8.ToArray(), CancellationToken.None);
            ProtectedEvidenceResponse? response = await store.TryReadResponseAsync(
                ticket.RequestId,
                CancellationToken.None);

            Assert.Null(response);
            Assert.True(File.Exists(ticket.ResponsePath));
        }

        store.DiscardRequest(ticket.RequestId);
    }

    [Fact]
    public async Task RequestStore_RoundTripsOneShotRequestAndResponse()
    {
        using var directory = new TestDirectory();
        string root = Path.Combine(directory.Path, "requests");
        var store = new ElevatedHelperRequestStore(root);
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.RetryNamedSource,
            ProtectedEvidenceSource.SystemEventLog,
            null,
            null,
            null,
            false,
            false,
            false);

        ElevatedHelperTicket ticket = await store.CreateRequestAsync(request, CancellationToken.None);
        Assert.True(File.Exists(ticket.RequestPath));
        Assert.StartsWith(Path.GetFullPath(root), ticket.RequestPath, StringComparison.OrdinalIgnoreCase);

        ProtectedEvidenceRequest consumed = await store.ConsumeRequestAsync(ticket.RequestId, CancellationToken.None);
        Assert.Equal(request, consumed);
        Assert.False(File.Exists(ticket.RequestPath));

        var response = new ProtectedEvidenceResponse(true, "done");
        await store.PublishResponseAsync(ticket.RequestId, response, CancellationToken.None);
        ProtectedEvidenceResponse? received = await store.TryReadResponseAsync(ticket.RequestId, CancellationToken.None);
        Assert.Equal(response, received);
        Assert.False(File.Exists(ticket.ResponsePath));
        Assert.Null(await store.TryReadResponseAsync(ticket.RequestId, CancellationToken.None));
    }

    [Theory]
    [InlineData("../outside")]
    [InlineData("0000000000000000000000000000000g")]
    [InlineData("too-short")]
    public async Task RequestStore_RejectsTraversalAndInvalidIds(string requestId)
    {
        using var directory = new TestDirectory();
        var store = new ElevatedHelperRequestStore(Path.Combine(directory.Path, "requests"));

        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.ConsumeRequestAsync(requestId, CancellationToken.None));
    }

    [Fact]
    public async Task RequestStore_RejectsOversizedMessageAndDeletesIt()
    {
        using var directory = new TestDirectory();
        string root = Path.Combine(directory.Path, "requests");
        var store = new ElevatedHelperRequestStore(root);
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.RetryNamedSource,
            ProtectedEvidenceSource.SystemEventLog,
            null,
            null,
            null,
            false,
            false,
            false);
        ElevatedHelperTicket ticket = await store.CreateRequestAsync(request, CancellationToken.None);
        await File.WriteAllBytesAsync(ticket.RequestPath, new byte[70 * 1024], CancellationToken.None);

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.ConsumeRequestAsync(ticket.RequestId, CancellationToken.None));

        Assert.False(File.Exists(ticket.RequestPath));
    }

    [Fact]
    public async Task RequestStore_ResponseCannotOverwriteExistingFile()
    {
        using var directory = new TestDirectory();
        var store = new ElevatedHelperRequestStore(Path.Combine(directory.Path, "requests"));
        var request = new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.RetryNamedSource,
            ProtectedEvidenceSource.SystemEventLog,
            null,
            null,
            null,
            false,
            false,
            false);
        ElevatedHelperTicket ticket = await store.CreateRequestAsync(request, CancellationToken.None);
        var response = new ProtectedEvidenceResponse(true, "done");

        await store.PublishResponseAsync(ticket.RequestId, response, CancellationToken.None);
        await Assert.ThrowsAsync<IOException>(() =>
            store.PublishResponseAsync(ticket.RequestId, response, CancellationToken.None));
    }

    [Fact]
    public async Task RequestStore_MalformedCompletedResponseIsRejectedAndDeleted()
    {
        using var directory = new TestDirectory();
        var store = new ElevatedHelperRequestStore(Path.Combine(directory.Path, "requests"));
        ElevatedHelperTicket ticket = await store.CreateRequestAsync(
            new ProtectedEvidenceRequest(
                ProtectedEvidenceOperation.RetryNamedSource,
                ProtectedEvidenceSource.SystemEventLog,
                null,
                null,
                null,
                false,
                false,
                false),
            CancellationToken.None);
        await File.WriteAllTextAsync(ticket.ResponsePath, "{not-json}", CancellationToken.None);

        await Assert.ThrowsAsync<JsonException>(() =>
            store.TryReadResponseAsync(ticket.RequestId, CancellationToken.None));

        Assert.False(File.Exists(ticket.ResponsePath));
        store.DiscardRequest(ticket.RequestId);
    }

    [Fact]
    public async Task RequestStore_CancellationMarkerIsFixedAndOneShot()
    {
        using var directory = new TestDirectory();
        var store = new ElevatedHelperRequestStore(Path.Combine(directory.Path, "requests"));
        ElevatedHelperTicket ticket = await store.CreateRequestAsync(
            new ProtectedEvidenceRequest(
                ProtectedEvidenceOperation.RetryNamedSource,
                ProtectedEvidenceSource.SystemEventLog,
                null,
                null,
                null,
                false,
                false,
                false),
            CancellationToken.None);

        store.RequestCancellation(ticket.RequestId);
        store.RequestCancellation(ticket.RequestId);
        Assert.True(store.IsCancellationRequested(ticket.RequestId));

        store.ClearCancellation(ticket.RequestId);
        Assert.False(store.IsCancellationRequested(ticket.RequestId));
    }
}
