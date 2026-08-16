using System.Text.Json;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class StorageHealthCollectorTests
{
    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Collector_JoinsReliabilityInternallyWithoutExportingPersistentIdentifier()
    {
        const string privateDeviceId = "PCI\\VEN_1234\\SERIAL-S3CRET";
        var source = new FakeStorageSource(new StorageHealthSourceResult(
            [new RawStorageDevice(privateDeviceId, "Example NVMe", 4, 17, "FW1", 1, [2, 5], 1_000_000)],
            [new RawStorageReliability(privateDeviceId, 45, 70, 12, 10, 1, 20, 2, 3, 4, 5, 900)],
            [new CollectionStatus("storage", CollectionState.Available, "read")]));
        var collector = new StorageHealthCollector(source, TimeProvider.System);

        StorageHealthSnapshot snapshot = await collector.CollectAsync();

        StorageHealthRecord record = Assert.Single(snapshot.Devices);
        Assert.Equal(1, record.Ordinal);
        Assert.Equal("Example NVMe", record.Model);
        Assert.Equal("SSD", record.MediaType);
        Assert.Equal("NVMe", record.BusType);
        Assert.Equal("Warning", record.HealthStatus);
        Assert.Equal(["OK", "Predictive failure"], record.OperationalStatus);
        Assert.Equal((byte)45, record.TemperatureCelsius);
        Assert.Equal((byte)12, record.WearPercent);
        Assert.Equal((ulong)1, record.ReadErrorsUncorrected);
        string json = JsonSerializer.Serialize(snapshot);
        Assert.DoesNotContain("DeviceId", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SERIAL-S3CRET", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("UniqueId", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PhysicalLocation", json, StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public void CreateRecord_MapsUnknownAndMissingProviderValuesWithoutGuessing()
    {
        StorageHealthRecord record = StorageHealthCollector.CreateRecord(
            2,
            new RawStorageDevice("private", string.Empty, null, 99, string.Empty, null, [], null),
            reliability: null);

        Assert.Equal("Unknown model", record.Model);
        Assert.Equal("Unavailable", record.MediaType);
        Assert.Equal("Other (99)", record.BusType);
        Assert.Equal("Unavailable", record.HealthStatus);
        Assert.Null(record.TemperatureCelsius);
        Assert.Null(record.WearPercent);
        Assert.Empty(record.OperationalStatus);
    }

    private sealed class FakeStorageSource(StorageHealthSourceResult result) : IStorageHealthSource
    {
        public StorageHealthSourceResult Read(CancellationToken cancellationToken) => result;
    }
}
