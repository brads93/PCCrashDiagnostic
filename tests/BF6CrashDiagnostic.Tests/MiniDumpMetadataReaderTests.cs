using System.Buffers.Binary;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class MiniDumpMetadataReaderTests
{
    [Fact]
    public void Read_UsesDocumentedStreamsForBoundedUserModeMetadata()
    {
        using var directory = new TestDirectory();
        string path = Path.Combine(directory.Path, "valid.dmp");
        File.WriteAllBytes(path, CreateMiniDump());
        DumpCandidate candidate = new SafeDumpInspector().Inspect(path, DumpKind.ApplicationDump, "fixture");

        MiniDumpMetadata metadata = new MiniDumpMetadataReader().Read(candidate);

        Assert.Equal(MiniDumpMetadataState.ParsedUserModeMiniDump, metadata.State);
        Assert.Equal(DumpFormat.MiniDump, metadata.Format);
        Assert.Equal("x64", metadata.ProcessorArchitecture);
        Assert.Equal(16, metadata.ProcessorCount);
        Assert.Equal(10, metadata.WindowsMajorVersion);
        Assert.Equal(0, metadata.WindowsMinorVersion);
        Assert.Equal(26100, metadata.WindowsBuildNumber);
        Assert.Equal(4242u, metadata.ProcessId);
        Assert.Equal(3, metadata.ThreadCount);
        Assert.Equal(2, metadata.ModuleCount);
        Assert.Contains("SystemInfoStream", metadata.StreamsRead);
        Assert.Contains("MiscInfoStream", metadata.StreamsRead);
        Assert.Contains("ThreadListStream", metadata.StreamsRead);
        Assert.Contains("ModuleListStream", metadata.StreamsRead);
    }

    [Fact]
    public void Read_KernelDumpRemainsHeaderOnly()
    {
        using var directory = new TestDirectory();
        string path = Path.Combine(directory.Path, "kernel.dmp");
        byte[] bytes = new byte[4096];
        "PAGEDU64"u8.CopyTo(bytes);
        File.WriteAllBytes(path, bytes);
        DumpCandidate candidate = new SafeDumpInspector().Inspect(path, DumpKind.WindowsMemoryDump, "fixture");

        MiniDumpMetadata metadata = new MiniDumpMetadataReader().Read(candidate);

        Assert.Equal(MiniDumpMetadataState.RecognizedKernelDump, metadata.State);
        Assert.Equal(DumpFormat.PageDump64, metadata.Format);
        Assert.Empty(metadata.StreamsRead);
        Assert.Contains("Only signature metadata", metadata.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Read_RejectsTruncatedAndChangedCandidates()
    {
        using var directory = new TestDirectory();
        string truncatedPath = Path.Combine(directory.Path, "truncated.dmp");
        File.WriteAllBytes(truncatedPath, "MDMP"u8.ToArray());
        DumpCandidate truncated = new SafeDumpInspector().Inspect(
            truncatedPath,
            DumpKind.ApplicationDump,
            "fixture");
        Assert.Equal(MiniDumpMetadataState.Invalid, new MiniDumpMetadataReader().Read(truncated).State);

        string changedPath = Path.Combine(directory.Path, "changed.dmp");
        File.WriteAllBytes(changedPath, CreateMiniDump());
        DumpCandidate changed = new SafeDumpInspector().Inspect(changedPath, DumpKind.ApplicationDump, "fixture");
        using (var append = new FileStream(changedPath, FileMode.Append, FileAccess.Write, FileShare.Read))
        {
            append.WriteByte(0xCC);
        }

        Assert.Equal(MiniDumpMetadataState.Unavailable, new MiniDumpMetadataReader().Read(changed).State);
    }

    [Fact]
    public void Read_RejectsCorruptContainer()
    {
        using var directory = new TestDirectory();
        string path = Path.Combine(directory.Path, "corrupt.dmp");
        File.WriteAllBytes(path, new byte[128]);
        DumpCandidate candidate = new SafeDumpInspector().Inspect(path, DumpKind.ApplicationDump, "fixture");

        MiniDumpMetadata metadata = new MiniDumpMetadataReader().Read(candidate);

        Assert.Equal(MiniDumpMetadataState.Unrecognized, metadata.State);
    }

    private static byte[] CreateMiniDump()
    {
        const int headerOffset = 0;
        const int directoryOffset = 32;
        const int streamCount = 4;
        const int systemInfoOffset = directoryOffset + streamCount * 12;
        const int systemInfoSize = 56;
        const int miscInfoOffset = systemInfoOffset + systemInfoSize;
        const int miscInfoSize = 24;
        const int threadListOffset = miscInfoOffset + miscInfoSize;
        const int moduleListOffset = threadListOffset + 4;
        byte[] bytes = new byte[moduleListOffset + 4];

        "MDMP"u8.CopyTo(bytes.AsSpan(headerOffset, 4));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4, 4), 0x0000A793);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), streamCount);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, 4), directoryOffset);

        WriteDirectory(bytes, directoryOffset, 7, systemInfoSize, systemInfoOffset);
        WriteDirectory(bytes, directoryOffset + 12, 15, miscInfoSize, miscInfoOffset);
        WriteDirectory(bytes, directoryOffset + 24, 3, 4, threadListOffset);
        WriteDirectory(bytes, directoryOffset + 36, 4, 4, moduleListOffset);

        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(systemInfoOffset, 2), 9);
        bytes[systemInfoOffset + 6] = 16;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(systemInfoOffset + 8, 4), 10);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(systemInfoOffset + 12, 4), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(systemInfoOffset + 16, 4), 26100);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(systemInfoOffset + 20, 4), 2);

        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(miscInfoOffset, 4), miscInfoSize);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(miscInfoOffset + 4, 4), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(miscInfoOffset + 8, 4), 4242);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(miscInfoOffset + 12, 4), 1_700_000_000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(threadListOffset, 4), 3);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(moduleListOffset, 4), 2);
        return bytes;
    }

    private static void WriteDirectory(byte[] bytes, int offset, int type, int size, int rva)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset, 4), checked((uint)type));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 4, 4), checked((uint)size));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset + 8, 4), checked((uint)rva));
    }
}
