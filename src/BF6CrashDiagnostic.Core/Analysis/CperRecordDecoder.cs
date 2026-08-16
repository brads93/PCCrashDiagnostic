using System.Buffers.Binary;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Classifies documented CPER section descriptors without retaining section payload bytes.
/// Unknown or malformed records remain generic and never identify a defective component.
/// </summary>
public static class CperRecordDecoder
{
    private const int HeaderSize = 128;
    private const int SectionDescriptorSize = 72;
    private const int MaximumRecordBytes = 4 * 1024 * 1024;
    private const int MaximumSections = 64;

    private static readonly HashSet<Guid> ProcessorSections =
    [
        new("9876CCAD-47B4-4BDB-B65E-16F193C4F3DB"),
        new("DC3EA0B0-A144-4797-B95B-53FA242B6E1D")
    ];

    private static readonly HashSet<Guid> MemorySections =
    [
        new("A5BC1114-6F64-4EDE-B863-3E83ED7C83B1")
    ];

    private static readonly HashSet<Guid> PcieSections =
    [
        new("D995E954-BBC1-430F-AD91-B44DCB3C6F35"),
        new("C5753963-3B84-4095-BF78-EDDAD3F9C9DD"),
        new("EB5E4685-CA66-4769-B6A2-26068B001326")
    ];

    public static bool TryClassifyBase64(string? encodedRecord, out IReadOnlyList<string> categories)
    {
        categories = [];
        if (string.IsNullOrWhiteSpace(encodedRecord) || encodedRecord.Length > MaximumRecordBytes * 2)
        {
            return false;
        }

        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(encodedRecord.Trim());
        }
        catch (FormatException)
        {
            return false;
        }

        return TryClassify(bytes, out categories);
    }

    public static bool TryClassify(ReadOnlySpan<byte> record, out IReadOnlyList<string> categories)
    {
        categories = [];
        if (record.Length < HeaderSize || record.Length > MaximumRecordBytes ||
            !record[..4].SequenceEqual("CPER"u8))
        {
            return false;
        }

        int sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(record.Slice(10, 2));
        uint declaredLength = BinaryPrimitives.ReadUInt32LittleEndian(record.Slice(20, 4));
        if (sectionCount is <= 0 or > MaximumSections ||
            declaredLength < HeaderSize || declaredLength > record.Length ||
            HeaderSize + sectionCount * SectionDescriptorSize > declaredLength)
        {
            return false;
        }

        var result = new HashSet<string>(StringComparer.Ordinal);
        for (int index = 0; index < sectionCount; index++)
        {
            int descriptorOffset = HeaderSize + index * SectionDescriptorSize;
            uint sectionOffset = BinaryPrimitives.ReadUInt32LittleEndian(record.Slice(descriptorOffset, 4));
            uint sectionLength = BinaryPrimitives.ReadUInt32LittleEndian(record.Slice(descriptorOffset + 4, 4));
            if (sectionOffset > declaredLength || sectionLength > declaredLength - sectionOffset)
            {
                return false;
            }

            Guid sectionType = new(record.Slice(descriptorOffset + 16, 16));
            result.Add(Classify(sectionType));
        }

        categories = result.Order(StringComparer.Ordinal).ToArray();
        return true;
    }

    private static string Classify(Guid sectionType)
    {
        if (ProcessorSections.Contains(sectionType))
        {
            return "Processor";
        }

        if (MemorySections.Contains(sectionType))
        {
            return "Memory";
        }

        return PcieSections.Contains(sectionType) ? "PCIe" : "Generic hardware";
    }
}
