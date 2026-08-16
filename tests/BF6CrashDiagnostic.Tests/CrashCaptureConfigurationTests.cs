using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class CrashCaptureConfigurationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 5, 14, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Readiness_DetectsActiveDumpFromFilterPagesAndRawTenCompatibility()
    {
        var values = AutomaticCrashValues();
        values["CrashDumpEnabled"] = 1;
        values["FilterPages"] = 1;
        CrashReadiness filtered = CrashReadinessCollector.CreateReadiness(
            Now,
            values,
            new[] { @"C:\pagefile.sys 0 0" },
            100,
            200,
            ReadyRuntime(),
            ReadyDestination(),
            ReadyDestination());

        values["CrashDumpEnabled"] = 10;
        values["FilterPages"] = 0;
        CrashReadiness rawTen = CrashReadinessCollector.CreateReadiness(
            Now,
            values,
            new[] { @"C:\pagefile.sys 0 0" },
            100,
            200,
            ReadyRuntime(),
            ReadyDestination(),
            ReadyDestination());

        Assert.Equal(CrashDumpMode.ActiveMemory, filtered.DumpMode);
        Assert.True(filtered.ActiveDumpFilterEnabled);
        Assert.Equal(CrashDumpMode.ActiveMemory, rawTen.DumpMode);
        Assert.False(rawTen.ActiveDumpFilterEnabled);
    }

    [Fact]
    public void Readiness_UsesExplicitOffAndPendingRestartStates()
    {
        var offValues = AutomaticCrashValues();
        offValues["CrashDumpEnabled"] = 0;
        CrashReadiness off = CrashReadinessCollector.CreateReadiness(
            Now,
            offValues,
            Array.Empty<string>(),
            100,
            200);
        var receipt = new CrashCaptureReceipt(
            1,
            new string('b', 32),
            new string('c', 32),
            "test-session",
            new string('a', 64),
            Now.AddMinutes(-1),
            Now.AddHours(-2),
            [],
            CrashCaptureActivationState.PendingRestart,
            null,
            Restored: false);
        CrashReadiness pending = CrashReadinessCollector.CreateReadiness(
            Now,
            AutomaticCrashValues(),
            new[] { @"C:\pagefile.sys 0 0" },
            100,
            200,
            ReadyRuntime() with { BootUtc = Now.AddHours(-2) },
            ReadyDestination(),
            ReadyDestination(),
            receipt);

        Assert.Equal(CrashReadinessState.Off, off.Assessment);
        Assert.Equal(CrashReadinessState.PendingRestart, pending.Assessment);
        Assert.Equal(CrashCaptureActivationState.PendingRestart, pending.ActivationState);
        Assert.Equal(receipt.AppliedUtc, pending.ConfigurationAppliedUtc);
    }

    [Fact]
    public void Readiness_ReportsFixedPagefileAndDedicatedCapacityWithoutPaths()
    {
        const long gib = 1024L * 1024 * 1024;
        var values = AutomaticCrashValues();
        values["CrashDumpEnabled"] = 1;
        values["FilterPages"] = 0;
        values["DedicatedDumpFile"] = @"D:\private\dedicated.sys";
        values["DumpFileSize"] = 2048;
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            Now,
            values,
            new[] { @"C:\pagefile.sys 1024 4096" },
            100,
            200,
            new PageFileRuntimeSnapshot(false, 1, 4 * gib, Now.AddHours(-2), 32 * gib),
            ReadyDestination(),
            ReadyDestination(),
            null,
            new DestinationCapacity(true, 20 * gib, 100 * gib, 2 * gib));

        Assert.Equal(1 * gib, actual.ConfiguredPageFileMinimumBytes);
        Assert.Equal(4 * gib, actual.ConfiguredPageFileMaximumBytes);
        Assert.Equal(2 * gib, actual.DedicatedDumpConfiguredBytes);
        Assert.Equal(2 * gib, actual.DedicatedDumpActualBytes);
        Assert.Equal(20 * gib, actual.DedicatedDumpDestinationFreeBytes);
        Assert.Equal((32 * gib) + (257L * 1024 * 1024), actual.RequiredDumpBackingBytes);
        Assert.Equal(CrashReadinessState.AtRisk, actual.Assessment);
        Assert.DoesNotContain("private", System.Text.Json.JsonSerializer.Serialize(actual), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Readiness_AutomaticUsesRamAwareRecommendationAndFlagsUndersizedBacking()
    {
        const long gib = 1024L * 1024 * 1024;
        const long expected = 32 * gib;
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            Now,
            AutomaticCrashValues(),
            new[] { @"C:\pagefile.sys 1024 8192" },
            100 * gib,
            200 * gib,
            new PageFileRuntimeSnapshot(false, 1, 8 * gib, Now.AddHours(-2), 64 * gib),
            ReadyDestination(),
            ReadyDestination());

        Assert.Null(actual.RequiredDumpBackingBytes);
        Assert.Equal(expected, actual.RecommendedDumpBackingBytes);
        Assert.Equal(expected, actual.RecommendedDestinationFreeBytes);
        Assert.Equal(CrashReadinessState.AtRisk, actual.Assessment);
    }

    [Fact]
    public void Readiness_DedicatedBackingVolumeFreeSpaceAffectsAssessment()
    {
        const long gib = 1024L * 1024 * 1024;
        var values = AutomaticCrashValues();
        values["DedicatedDumpFile"] = @"D:\DedicatedDump.sys";
        values["DumpFileSize"] = 40 * 1024;
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            Now,
            values,
            Array.Empty<string>(),
            100 * gib,
            200 * gib,
            new PageFileRuntimeSnapshot(false, 0, null, Now.AddHours(-2), 64 * gib),
            ReadyDestination(),
            ReadyDestination(),
            null,
            new DestinationCapacity(true, 1 * gib, 100 * gib, 40 * gib));

        Assert.Equal(CrashReadinessState.AtRisk, actual.Assessment);
        Assert.Contains("dedicated dump-file volume", actual.AssessmentDetail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Readiness_ExistingDumpWithOverwriteDisabledIsAtRisk()
    {
        const long gib = 1024L * 1024 * 1024;
        var values = AutomaticCrashValues();
        values["Overwrite"] = 0;
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            Now,
            values,
            new[] { @"C:\pagefile.sys 0 0" },
            100 * gib,
            200 * gib,
            ReadyRuntime(),
            new DestinationCapacity(true, 100 * gib, 200 * gib, 4 * gib),
            ReadyDestination());

        Assert.Equal(CrashReadinessState.AtRisk, actual.Assessment);
        Assert.Contains("overwrite is disabled", actual.AssessmentDetail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Readiness_MalformedRegistryValueKindIsUnavailable()
    {
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            Now,
            AutomaticCrashValues(),
            new[] { @"C:\pagefile.sys 0 0" },
            100,
            200,
            ReadyRuntime(),
            ReadyDestination(),
            ReadyDestination(),
            malformedRegistryValues: ["CrashDumpEnabled"]);

        Assert.Equal(CrashReadinessState.Unavailable, actual.Assessment);
        Assert.Contains("registry type", actual.AssessmentDetail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Readiness_DoesNotMaskSavedReceiptConflictAsPendingRestart()
    {
        var receipt = new CrashCaptureReceipt(
            1,
            new string('b', 32),
            new string('c', 32),
            "test-session",
            new string('a', 64),
            Now.AddMinutes(-1),
            Now.AddHours(-2),
            [],
            CrashCaptureActivationState.PendingRestart,
            null,
            Restored: false);
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            Now,
            AutomaticCrashValues(),
            new[] { @"C:\pagefile.sys 0 0" },
            100,
            200,
            ReadyRuntime() with { BootUtc = Now.AddHours(-2) },
            ReadyDestination(),
            ReadyDestination(),
            receipt,
            latestReceiptMatchesConfiguration: false);

        Assert.Equal(CrashReadinessState.Limited, actual.Assessment);
        Assert.Equal(CrashCaptureActivationState.Unknown, actual.ActivationState);
        Assert.Contains("no longer matches", actual.AssessmentDetail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Readiness_MatcherFailureCannotActivateSavedReceipt()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        ProtectedEvidenceHelper helper = new(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => false,
            store,
            receipts,
            new FixedTimeProvider(Now),
            Path.Combine(directory.Path, "WerDumps"));
        ProtectedEvidenceResponse applied = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.ApplyCrashCapturePlan,
                plan: CreateAutomaticPlan(store)));
        Assert.True(applied.Succeeded, applied.Message);
        store.ReadPageFileConfigurationFailure = new InvalidDataException("Synthetic malformed PagingFiles.");
        var collector = new CrashReadinessCollector(new FixedTimeProvider(Now), store, receipts);

        CrashReadinessCollection result = await collector.CollectAsync();

        Assert.Equal(CrashCaptureActivationState.Unknown, result.Readiness.ActivationState);
        Assert.Contains(result.Statuses, status =>
            status.Source == "Crash readiness/Activation receipt" &&
            status.State == CollectionState.Unavailable);
    }

    [Fact]
    public async Task Readiness_MalformedSavedReceiptCannotActivatePendingState()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        receipts.Save(new CrashCaptureReceipt(
            1,
            new string('b', 32),
            new string('c', 32),
            "test-session",
            new string('a', 64),
            Now.AddMinutes(-1),
            Now.AddHours(-2),
            null!,
            CrashCaptureActivationState.PendingRestart,
            null,
            Restored: false));
        var collector = new CrashReadinessCollector(new FixedTimeProvider(Now), store, receipts);

        CrashReadinessCollection result = await collector.CollectAsync();

        Assert.Equal(CrashCaptureActivationState.Unknown, result.Readiness.ActivationState);
        Assert.Contains(result.Statuses, status =>
            status.Source == "Crash readiness/Activation receipt" &&
            status.State == CollectionState.Unavailable);
    }

    [Theory]
    [InlineData(@"\\server\share\MEMORY.DMP")]
    [InlineData(@"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\MEMORY.DMP")]
    [InlineData(@"\\.\PhysicalDrive0")]
    [InlineData(@"relative\MEMORY.DMP")]
    public void DestinationGuard_RejectsNonLocalOrDevicePathsBeforeProbe(string path)
    {
        Assert.False(WindowsCrashCaptureConfigurationStore.TryNormalizeLocalFixedDrivePath(
            path,
            out string fullPath,
            out DriveInfo? drive));
        Assert.Equal(string.Empty, fullPath);
        Assert.Null(drive);
    }

    [Fact]
    public void AutomaticPreset_RequestsSystemManagedPagefileForUnknownOrUndersizedBacking()
    {
        const long gib = 1024L * 1024 * 1024;
        CrashCaptureEnvironmentSnapshot undersized = new(
            false,
            true,
            1 * gib,
            8 * gib,
            null,
            null,
            null,
            new PageFileRuntimeSnapshot(false, 1, 8 * gib, Now.AddHours(-2), 64 * gib));
        CrashCaptureEnvironmentSnapshot unknownDedicated = undersized with
        {
            DedicatedDumpFileConfigured = true,
            DedicatedDumpConfiguredBytes = null,
            DedicatedDumpActualBytes = null
        };
        CrashCaptureEnvironmentSnapshot sufficient = undersized with
        {
            ConfiguredPageFileMaximumBytes = 40 * gib,
            RuntimePageFiles = undersized.RuntimePageFiles with { RuntimeAllocatedBytes = 40 * gib }
        };
        CrashCaptureEnvironmentSnapshot inaccessibleDedicated = undersized with
        {
            ConfiguredPageFilePresent = false,
            ConfiguredPageFileMaximumBytes = null,
            DedicatedDumpFileConfigured = true,
            DedicatedDumpConfiguredBytes = 40 * gib,
            DedicatedDumpDestinationAccessible = false,
            DedicatedDumpDestinationFreeBytes = 100 * gib,
            RuntimePageFiles = undersized.RuntimePageFiles with
            {
                RuntimePageFileCount = 0,
                RuntimeAllocatedBytes = null
            }
        };

        Assert.True(CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(undersized));
        Assert.True(CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(unknownDedicated));
        Assert.False(CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(sufficient));
        Assert.True(CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(inaccessibleDedicated));
        Assert.False(CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(
            undersized with
            {
                RuntimePageFiles = undersized.RuntimePageFiles with { AutomaticManagementEnabled = true }
            }));
    }

    [Fact]
    public void Readiness_AutomaticManagementFlagWithoutBootBackingIsAtRisk()
    {
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            Now,
            AutomaticCrashValues(),
            Array.Empty<string>(),
            100,
            200,
            new PageFileRuntimeSnapshot(
                true,
                0,
                null,
                Now.AddHours(-2),
                32L * 1024 * 1024 * 1024,
                BootVolumeRuntimeStateKnown: true),
            ReadyDestination(),
            ReadyDestination());

        Assert.Equal(CrashReadinessState.AtRisk, actual.Assessment);
        Assert.Contains("No configured or active page file", actual.AssessmentDetail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Helper_AppliesAutomaticPresetAndRestoresReceiptExactly()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);
        CrashCapturePlan plan = CreateAutomaticPlan(store);

        ProtectedEvidenceResponse applied = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyCrashCapturePlan, plan: plan));

        Assert.True(applied.Succeeded, applied.Message);
        CrashCaptureReceipt receipt = Assert.IsType<CrashCaptureReceipt>(applied.CrashCaptureReceipt);
        Assert.Equal(CrashCaptureActivationState.PendingRestart, receipt.ActivationState);
        Assert.Equal("7", store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
        Assert.False(store.ReadCrashSetting(CrashCaptureSetting.FilterPages).Exists);

        ProtectedEvidenceResponse restored = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.RestoreCrashCapturePlan,
                receiptId: receipt.ReceiptId));

        Assert.True(restored.Succeeded, restored.Message);
        Assert.True(restored.CrashCaptureReceipt?.Restored);
        Assert.Equal("3", store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
        Assert.Equal("1", store.ReadCrashSetting(CrashCaptureSetting.FilterPages).Value);
        Assert.Equal(@"D:\Old\MEMORY.DMP", store.ReadCrashSetting(CrashCaptureSetting.DumpFile).Value);
        Assert.False(store.PageFileConfiguration.AutomaticManagementEnabled);
        Assert.Equal([@"C:\pagefile.sys 1024 8192"], store.PageFileConfiguration.PagingFiles);
    }

    [Fact]
    public async Task Helper_CorrectsSupportedWrongRegistryKindAndRestoresExactPriorKind()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        store.Set(
            CrashCaptureSetting.CrashDumpEnabled,
            true,
            "7",
            (int)Microsoft.Win32.RegistryValueKind.String);
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);

        ProtectedEvidenceResponse applied = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.ApplyCrashCapturePlan,
                plan: CreateAutomaticPlan(store)));
        CrashCaptureReceipt receipt = Assert.IsType<CrashCaptureReceipt>(applied.CrashCaptureReceipt);
        Assert.Equal(
            (int)Microsoft.Win32.RegistryValueKind.DWord,
            store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).RegistryValueKind);

        ProtectedEvidenceResponse restored = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.RestoreCrashCapturePlan,
                receiptId: receipt.ReceiptId));

        Assert.True(restored.Succeeded, restored.Message);
        Assert.Equal("7", store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
        Assert.Equal(
            (int)Microsoft.Win32.RegistryValueKind.String,
            store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).RegistryValueKind);
    }

    [Fact]
    public async Task Helper_RefusesRestoreAfterLaterPagefileConfigurationChange()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);
        ProtectedEvidenceResponse applied = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.ApplyCrashCapturePlan,
                plan: CreateAutomaticPlan(store)));
        CrashCaptureReceipt receipt = Assert.IsType<CrashCaptureReceipt>(applied.CrashCaptureReceipt);
        Assert.NotNull(receipt.AppliedChanges.Single(change =>
            change.Setting == CrashCaptureSetting.AutomaticManagedPagefile).AppliedPageFileConfiguration);

        store.PageFileConfiguration = store.PageFileConfiguration with
        {
            PagingFiles = [@"C:\pagefile.sys 2048 16384"]
        };
        int writesBeforeRestore = store.WriteCount;

        ProtectedEvidenceResponse restored = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.RestoreCrashCapturePlan,
                receiptId: receipt.ReceiptId));

        Assert.False(restored.Succeeded);
        Assert.Contains("changed", restored.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(writesBeforeRestore, store.WriteCount);
        Assert.Equal([@"C:\pagefile.sys 2048 16384"], store.PageFileConfiguration.PagingFiles);
    }

    [Fact]
    public async Task Helper_CompareBeforeWriteAndRollbackPreventPartialConfiguration()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore changedStore = CreateInitialStore();
        CrashCapturePlan stalePlan = CreateAutomaticPlan(changedStore);
        changedStore.Set(CrashCaptureSetting.EventLogging, true, "1");
        ProtectedEvidenceHelper changedHelper = CreateConfigurationHelper(directory.Path, changedStore, "changed");

        ProtectedEvidenceResponse stale = await changedHelper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyCrashCapturePlan, plan: stalePlan));

        Assert.False(stale.Succeeded);
        Assert.Equal(0, changedStore.WriteCount);

        FakeConfigurationStore failingStore = CreateInitialStore();
        CrashCapturePlan failingPlan = CreateAutomaticPlan(failingStore);
        failingStore.DiscardWriteSetting = CrashCaptureSetting.DumpFile;
        failingStore.DiscardWritesRemaining = 1;
        ProtectedEvidenceHelper failingHelper = CreateConfigurationHelper(directory.Path, failingStore, "failing");

        ProtectedEvidenceResponse failed = await failingHelper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyCrashCapturePlan, plan: failingPlan));

        Assert.False(failed.Succeeded);
        Assert.True(failed.RollbackAttempted);
        Assert.True(failed.RollbackSucceeded);
        Assert.Equal("3", failingStore.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
        Assert.Equal("1", failingStore.ReadCrashSetting(CrashCaptureSetting.FilterPages).Value);
    }

    [Fact]
    public async Task Helper_RollsBackAWriteThatCommitsBeforeThrowing()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        store.ThrowAfterWriteSetting = CrashCaptureSetting.DumpFile;
        store.ThrowAfterWritesRemaining = 1;
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.ApplyCrashCapturePlan,
                plan: CreateAutomaticPlan(store)));

        Assert.False(response.Succeeded);
        Assert.True(response.RollbackAttempted);
        Assert.True(response.RollbackSucceeded);
        Assert.Equal("3", store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
        Assert.Equal(@"D:\Old\MEMORY.DMP", store.ReadCrashSetting(CrashCaptureSetting.DumpFile).Value);
    }

    [Fact]
    public async Task Helper_RollbackDoesNotOverwriteAnInterveningAdministratorChange()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        store.ThrowAfterWriteSetting = CrashCaptureSetting.DumpFile;
        store.ThrowAfterWritesRemaining = 1;
        store.AfterCrashWrite = setting =>
        {
            if (setting == CrashCaptureSetting.DumpFile)
            {
                store.Set(CrashCaptureSetting.CrashDumpEnabled, true, "5");
            }
        };
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.ApplyCrashCapturePlan,
                plan: CreateAutomaticPlan(store)));

        Assert.False(response.Succeeded);
        Assert.True(response.RollbackAttempted);
        Assert.False(response.RollbackSucceeded);
        Assert.Equal("5", store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
    }

    [Fact]
    public async Task Helper_RestoreWriteThenThrowRollsForwardPreparedConfiguration()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);
        ProtectedEvidenceResponse applied = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.ApplyCrashCapturePlan,
                plan: CreateAutomaticPlan(store)));
        CrashCaptureReceipt receipt = Assert.IsType<CrashCaptureReceipt>(applied.CrashCaptureReceipt);
        store.ThrowAfterWriteSetting = CrashCaptureSetting.OverwriteExistingDump;
        store.ThrowAfterWritesRemaining = 1;

        ProtectedEvidenceResponse restored = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.RestoreCrashCapturePlan,
                receiptId: receipt.ReceiptId));

        Assert.False(restored.Succeeded);
        Assert.True(restored.RollbackAttempted);
        Assert.True(restored.RollbackSucceeded);
        Assert.Equal("7", store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
        Assert.Equal("1", store.ReadCrashSetting(CrashCaptureSetting.OverwriteExistingDump).Value);
        Assert.True(store.PageFileConfiguration.AutomaticManagementEnabled);
    }

    [Fact]
    public async Task Helper_TargetStartingMidApplyDoesNotBlockRollback()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        bool targetStarted = false;
        store.AfterCrashWrite = setting =>
        {
            if (setting == CrashCaptureSetting.CrashDumpEnabled)
            {
                targetStarted = true;
            }
        };
        var helper = new ProtectedEvidenceHelper(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => targetStarted,
            store,
            new CrashCaptureReceiptStore(Path.Combine(directory.Path, "Receipts")),
            new FixedTimeProvider(Now),
            Path.Combine(directory.Path, "WerDumps"));

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.ApplyCrashCapturePlan,
                plan: CreateAutomaticPlan(store)));

        Assert.False(response.Succeeded);
        Assert.Equal("3", store.ReadCrashSetting(CrashCaptureSetting.CrashDumpEnabled).Value);
        Assert.Equal(@"D:\Old\MEMORY.DMP", store.ReadCrashSetting(CrashCaptureSetting.DumpFile).Value);
    }

    [Fact]
    public async Task Helper_WerOperationMatchesCompiledReleaseStage()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ => [EligibleWerProcess()]);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        if (ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            Assert.True(response.Succeeded, response.Message);
            Assert.Equal(1, store.WerWriteCount);
        }
        else
        {
            Assert.False(response.Succeeded);
            Assert.Contains("not enabled", response.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(0, store.WerWriteCount);
        }
    }

    [Fact]
    public async Task Helper_DisabledWerGateRejectsCraftedEmbeddedApplyWithoutWrites()
    {
        if (ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            return;
        }

        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan werPlan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        CrashCapturePlan crafted = CreateAutomaticPlan(store) with { WerLocalDumpPlan = werPlan };
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store, werRoot: werRoot);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyCrashCapturePlan, plan: crafted));

        Assert.False(response.Succeeded);
        Assert.Contains("not enabled", response.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, store.WriteCount);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_WerUsesFixedPrivateFolderAndFailsClosedAtCommitRace()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        TargetProfile target = UnprotectedTarget();
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, target);
        int checks = 0;
        var helper = new ProtectedEvidenceHelper(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => Interlocked.Increment(ref checks) >= 3,
            store,
            new CrashCaptureReceiptStore(Path.Combine(directory.Path, "Receipts")),
            new FixedTimeProvider(Now),
            werRoot);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
        Assert.False(Directory.Exists(plan.DesiredDumpFolder) && Directory.EnumerateFileSystemEntries(plan.DesiredDumpFolder).Any());
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_RejectsWerForProtectedProfileEvenWhenProcessIsClosed()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        TargetProfile protectedTarget = UnprotectedTarget() with { BlockSensitiveOperationsWhileRunning = true };
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, protectedTarget);
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store, werRoot: werRoot);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_PermanentlyRejectsBf6WerEvenWithOrdinaryProfileFlag()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        TargetProfile forgedOrdinaryBf6 = TargetProfile.Battlefield6 with
        {
            Id = "synthetic-bf6",
            BlockSensitiveOperationsWhileRunning = false
        };
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, forgedOrdinaryBf6, "BF6.exe");
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store, werRoot: werRoot);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureTheory]
    [InlineData("EAAntiCheat.GameService")]
    [InlineData("EAAntiCheat.GameServiceLauncher")]
    [InlineData("EAAntiCheatService")]
    public async Task Helper_PermanentlyRejectsEveryProtectedRelatedExecutableAlias(string processName)
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        TargetProfile forgedOrdinary = UnprotectedTarget() with
        {
            Id = "synthetic-protected-alias",
            ProcessNames = [processName],
            RelatedProcessNames = [],
            BlockSensitiveOperationsWhileRunning = false
        };
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, forgedOrdinary, processName + ".exe");
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store, werRoot: werRoot);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_RejectsCriticalWindowsExecutableWerPlan()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        TargetProfile target = UnprotectedTarget() with
        {
            Id = "synthetic-lsass",
            ProcessNames = ["lsass"]
        };
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, target, "lsass.exe");
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ => [EligibleWerProcess()]);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Helper_RequiresRunningNonSessionZeroOrdinaryAppForWer(bool sessionZeroOnly)
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ => sessionZeroOnly ? [EligibleWerProcess(sessionId: 0)] : []);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_AppliesWerForRunningUserSessionAppAfterStoragePreflight()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ => [EligibleWerProcess()]);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.True(response.Succeeded, response.Message);
        Assert.Equal(1, store.WerWriteCount);
        Assert.Contains("cannot be known", response.Message, StringComparison.OrdinalIgnoreCase);
        WerConfigurationSnapshot configured = store.ReadWerSettings(plan.ExecutableName);
        Assert.Equal((int)Microsoft.Win32.RegistryValueKind.DWord, configured.DumpType.RegistryValueKind);
        Assert.Equal((int)Microsoft.Win32.RegistryValueKind.DWord, configured.DumpCount.RegistryValueKind);
        Assert.Equal((int)Microsoft.Win32.RegistryValueKind.ExpandString, configured.DumpFolder.RegistryValueKind);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_RejectsWerWhenAnyMatchingInstanceCannotBeClassified()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ =>
            [
                EligibleWerProcess(),
                new WerProcessIdentity(-1, string.Empty, false, ClassificationSucceeded: false)
            ]);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_RejectsWerWhenAnyMatchingInstanceIsElevatedOrAnotherUser()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ =>
            [
                EligibleWerProcess(),
                EligibleWerProcess(elevated: true),
                EligibleWerProcess(ownerSid: "S-1-5-18")
            ]);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_WerWriteThenThrowRestoresPriorSettings()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        store.ThrowAfterWerWritesRemaining = 1;
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ => [EligibleWerProcess()]);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.True(response.RollbackAttempted);
        Assert.True(response.RollbackSucceeded);
        Assert.False(store.ReadWerSettings(plan.ExecutableName).KeyExists);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_WerRestoreWriteThenThrowRollsForwardAppliedSettings()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ => [EligibleWerProcess()]);
        ProtectedEvidenceResponse applied = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));
        WerLocalDumpReceipt receipt = Assert.IsType<WerLocalDumpReceipt>(applied.WerLocalDumpReceipt);
        store.ThrowAfterWerWritesRemaining = 1;

        ProtectedEvidenceResponse restored = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.RestoreWerLocalDumpPlan,
                receiptId: receipt.ReceiptId));

        Assert.False(restored.Succeeded);
        Assert.True(restored.RollbackAttempted);
        Assert.True(restored.RollbackSucceeded);
        Assert.Equal("2", store.ReadWerSettings(plan.ExecutableName).DumpType.Value);
        Assert.Equal("2", store.ReadWerSettings(plan.ExecutableName).DumpCount.Value);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_WerRestorePreservesLaterUnknownKeyContent()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(
            directory.Path,
            store,
            werRoot: werRoot,
            matchingProcessIdentities: _ => [EligibleWerProcess()]);
        ProtectedEvidenceResponse applied = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));
        WerLocalDumpReceipt receipt = Assert.IsType<WerLocalDumpReceipt>(applied.WerLocalDumpReceipt);
        store.PreserveWerKeyWhenRestoringAbsentOwnedValues = true;

        ProtectedEvidenceResponse restored = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.RestoreWerLocalDumpPlan,
                receiptId: receipt.ReceiptId));

        Assert.True(restored.Succeeded, restored.Message);
        WerConfigurationSnapshot current = store.ReadWerSettings(plan.ExecutableName);
        Assert.True(current.KeyExists);
        Assert.False(current.DumpType.Exists);
        Assert.False(current.DumpCount.Exists);
        Assert.False(current.DumpFolder.Exists);
    }

    [WerLocalDumpCaptureFact]
    public async Task Helper_WerStoragePreflightRejectsZeroFreeSpaceBeforeRegistryWrite()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan plan = CreateWerPlan(store, werRoot, UnprotectedTarget());
        var helper = new ProtectedEvidenceHelper(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => 0,
            () => false,
            store,
            new CrashCaptureReceiptStore(Path.Combine(directory.Path, "Receipts")),
            new FixedTimeProvider(Now),
            werRoot,
            _ => [EligibleWerProcess()]);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyWerLocalDumpPlan, werPlan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WerWriteCount);
        Assert.False(Directory.Exists(werRoot));
    }

    [Beta2Theory]
    [InlineData(false, new[] { "DumpType", "DumpCount", "DumpFolder" }, new string[0], true)]
    [InlineData(false, new[] { "DumpType", "VendorValue" }, new string[0], false)]
    [InlineData(false, new[] { "DumpType" }, new[] { "VendorSubkey" }, false)]
    [InlineData(true, new string[0], new string[0], false)]
    public void WerRestore_PreservesUnknownValuesAndSubkeys(
        bool previousKeyExisted,
        string[] values,
        string[] subkeys,
        bool expectedDelete)
    {
        Assert.Equal(
            expectedDelete,
            WindowsCrashCaptureConfigurationStore.ShouldDeleteWerKeyAfterRestore(
                previousKeyExisted,
                values,
                subkeys));
    }

    [Fact]
    public async Task Helper_WerRestoreRemainsAvailableWhenNewCaptureIsDisabled()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        string executable = "PccdSyntheticTarget.exe";
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        string appliedFolder = ProtectedEvidenceHelper.ApprovedWerDumpFolder(werRoot, executable);
        WerConfigurationSnapshot appliedSettings = new(
            true,
            new StoredConfigurationValue(true, "2", (int)Microsoft.Win32.RegistryValueKind.DWord),
            new StoredConfigurationValue(true, "2", (int)Microsoft.Win32.RegistryValueKind.DWord),
            new StoredConfigurationValue(true, appliedFolder, (int)Microsoft.Win32.RegistryValueKind.ExpandString));
        store.SetWer(executable, appliedSettings);
        var receipt = new WerLocalDumpReceipt(
            1,
            new string('e', 32),
            new string('d', 32),
            "test-session",
            new string('a', 64),
            Now,
            executable,
            PreviousKeyExists: false,
            PreviousDumpTypeExists: false,
            PreviousDumpType: null,
            PreviousDumpCountExists: false,
            PreviousDumpCount: null,
            PreviousDumpFolderExists: false,
            PreviousDumpFolder: null,
            AppliedDumpType: 2,
            AppliedDumpCount: 2,
            AppliedDumpFolder: appliedFolder,
            Restored: false,
            TargetProfile: UnprotectedTarget());
        var receipts = new CrashCaptureReceiptStore(Path.Combine(directory.Path, "Receipts"));
        receipts.Save(receipt);
        var helper = new ProtectedEvidenceHelper(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => false,
            store,
            receipts,
            new FixedTimeProvider(Now),
            werRoot);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(
                ProtectedEvidenceOperation.RestoreWerLocalDumpPlan,
                receiptId: receipt.ReceiptId));

        Assert.True(response.Succeeded, response.Message);
        Assert.False(store.ReadWerSettings(executable).DumpType.Exists);
        Assert.False(store.ReadWerSettings(executable).DumpCount.Exists);
        Assert.False(store.ReadWerSettings(executable).DumpFolder.Exists);
    }

    [Fact]
    public async Task Coordinator_PreviewsAndAppliesBoundPlanWithoutRewritingIncidentReport()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        ProtectedEvidenceHelper helper = new(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => false,
            store,
            receipts,
            TimeProvider.System,
            Path.Combine(directory.Path, "WerDumps"));
        var coordinator = new PCCrashDiagnosticCoordinator(
            directory.Path,
            (_, _) => Task.CompletedTask,
            new DirectHelperClient(helper),
            helper,
            new ElevatedHelperRequestStore(Path.Combine(directory.Path, "Requests")),
            () => false,
            _ => true,
            null,
            store,
            receipts,
            _ => Task.FromResult(new CrashReadinessCollection(ReadyReadiness(), [])));
        DiagnosticOperationResultV3 report = BoundReport(directory.Path);

        CrashCapturePlan preview = await coordinator.PreviewCrashCapturePreparationAsync(report);
        CrashCapturePreparationResult applied = await coordinator.PrepareCrashCaptureAsync(report, preview);

        Assert.NotEmpty(preview.Changes);
        Assert.True(applied.Succeeded, applied.Message);
        Assert.NotNull(applied.Receipt);
        Assert.Equal(CrashReadinessState.PendingRestart, applied.AfterReadiness?.Assessment);
        Assert.Same(report.Package.Report, report.Package.Report);
    }

    [Fact]
    public async Task Coordinator_DoesNotMaskGroupPolicyReversionAsPendingRestart()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        ProtectedEvidenceHelper helper = new(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => false,
            store,
            receipts,
            TimeProvider.System,
            Path.Combine(directory.Path, "WerDumps"));
        int readinessCalls = 0;
        Task<CrashReadinessCollection> Collect(CancellationToken _)
        {
            if (Interlocked.Increment(ref readinessCalls) == 2)
            {
                store.Set(CrashCaptureSetting.EventLogging, true, "0");
            }

            return Task.FromResult(new CrashReadinessCollection(ReadyReadiness(), []));
        }

        using var coordinator = new PCCrashDiagnosticCoordinator(
            directory.Path,
            (_, _) => Task.CompletedTask,
            new DirectHelperClient(helper),
            helper,
            new ElevatedHelperRequestStore(Path.Combine(directory.Path, "Requests")),
            () => false,
            _ => false,
            null,
            store,
            receipts,
            Collect);
        DiagnosticOperationResultV3 report = BoundReport(directory.Path);
        CrashCapturePlan preview = await coordinator.PreviewCrashCapturePreparationAsync(report);

        CrashCapturePreparationResult result = await coordinator.PrepareCrashCaptureAsync(report, preview);

        Assert.False(result.Succeeded);
        Assert.Contains("Group Policy", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(CrashReadinessState.PendingRestart, result.AfterReadiness?.Assessment);
    }

    [Fact]
    public async Task Coordinator_FailsPreviewWhenAutomaticFlagHasNoBootBacking()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        store.Environment = store.Environment with
        {
            ConfiguredPageFilePresent = false,
            ConfiguredPageFileMinimumBytes = null,
            ConfiguredPageFileMaximumBytes = null,
            BootVolumeConfiguredPageFilePresent = false,
            BootVolumeConfiguredPageFileMinimumBytes = null,
            BootVolumeConfiguredPageFileMaximumBytes = null,
            RuntimePageFiles = store.Environment.RuntimePageFiles with
            {
                AutomaticManagementEnabled = true,
                RuntimePageFileCount = 0,
                RuntimeAllocatedBytes = null,
                BootVolumeRuntimePageFileCount = 0,
                BootVolumeRuntimeAllocatedBytes = null,
                BootVolumeRuntimeStateKnown = true
            }
        };
        store.Set(CrashCaptureSetting.AutomaticManagedPagefile, true, "true");
        store.PageFileConfiguration = new PageFileConfigurationSnapshot(true, true, true, []);
        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, store, receipts, helper);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.PreviewCrashCapturePreparationAsync(BoundReport(directory.Path)));

        Assert.Contains("no boot-volume page file", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, store.WriteCount);
    }

    [Fact]
    public async Task Helper_IndependentlyRejectsAutomaticFlagWithoutBootBacking()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        store.Environment = store.Environment with
        {
            ConfiguredPageFilePresent = false,
            BootVolumeConfiguredPageFilePresent = false,
            RuntimePageFiles = store.Environment.RuntimePageFiles with
            {
                AutomaticManagementEnabled = true,
                RuntimePageFileCount = 0,
                RuntimeAllocatedBytes = null,
                BootVolumeRuntimePageFileCount = 0,
                BootVolumeRuntimeAllocatedBytes = null,
                BootVolumeRuntimeStateKnown = true
            }
        };
        store.Set(CrashCaptureSetting.AutomaticManagedPagefile, true, "true");
        store.PageFileConfiguration = new PageFileConfigurationSnapshot(true, true, true, []);
        CrashCapturePlan crafted = CreateAutomaticPlan(store);
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyCrashCapturePlan, plan: crafted));

        Assert.False(response.Succeeded);
        Assert.Contains("without configured or active boot-volume", response.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, store.WriteCount);
    }

    [Fact]
    public async Task Helper_BlocksWhenOnlyRelatedProtectedProcessIsRunning()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        TargetProfile target = UnprotectedTarget() with
        {
            BlockSensitiveOperationsWhileRunning = true,
            ProcessNames = ["PrimaryNotRunning"],
            RelatedProcessNames = ["RelatedRunning"]
        };
        CrashCapturePlan plan = CreateAutomaticPlan(store) with { TargetProfile = target };
        var helper = new ProtectedEvidenceHelper(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => false,
            store,
            new CrashCaptureReceiptStore(Path.Combine(directory.Path, "Receipts")),
            new FixedTimeProvider(Now),
            Path.Combine(directory.Path, "WerDumps"),
            matchingProcessIdentities: _ => [EligibleWerProcess()],
            originatingUserSid: null,
            isNamedProcessRunning: name => name.Equals("RelatedRunning", StringComparison.OrdinalIgnoreCase));

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            ConfigurationRequest(ProtectedEvidenceOperation.ApplyCrashCapturePlan, plan: plan));

        Assert.False(response.Succeeded);
        Assert.Equal(0, store.WriteCount);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Coordinator_FailsPreviewBeforeUacForMalformedPrerequisiteTypes(bool malformedPagefile)
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        if (malformedPagefile)
        {
            store.ReadPageFileConfigurationFailure = new InvalidDataException("Synthetic malformed PagingFiles.");
        }
        else
        {
            store.Set(
                CrashCaptureSetting.CrashDumpEnabled,
                true,
                "binary-value",
                (int)Microsoft.Win32.RegistryValueKind.Binary);
        }

        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, store, receipts, helper);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            coordinator.PreviewCrashCapturePreparationAsync(BoundReport(directory.Path)));
        Assert.Equal(0, store.WriteCount);
    }

    [Fact]
    public async Task Coordinator_WerPreviewRequiresOrdinaryConfirmationAndAlwaysRejectsBf6()
    {
        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, store, receipts, helper);
        TargetProfile protectedGeneric = UnprotectedTarget() with { BlockSensitiveOperationsWhileRunning = true };
        DiagnosticOperationResultV3 genericReport = BoundReport(directory.Path, protectedGeneric);

        if (!ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            await Assert.ThrowsAsync<NotSupportedException>(() =>
                coordinator.PreviewWerLocalDumpPlanAsync(genericReport));
            await Assert.ThrowsAsync<NotSupportedException>(() =>
                coordinator.PreviewWerLocalDumpPlanAsync(
                    genericReport,
                    ordinaryAppConfirmed: true));
            return;
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.PreviewWerLocalDumpPlanAsync(genericReport));
        WerLocalDumpPlan confirmed = await coordinator.PreviewWerLocalDumpPlanAsync(
            genericReport,
            ordinaryAppConfirmed: true);

        Assert.False(confirmed.TargetProfile?.BlockSensitiveOperationsWhileRunning);

        DiagnosticOperationResultV3 bf6Report = BoundReport(directory.Path, TargetProfile.Battlefield6);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.PreviewWerLocalDumpPlanAsync(
                bf6Report,
                ordinaryAppConfirmed: true));
    }

    [Fact]
    public async Task Coordinator_DisabledWerGateRejectsStandaloneAndEmbeddedApplyBeforeHelper()
    {
        if (ReleaseStage.WerLocalDumpCaptureEnabled)
        {
            return;
        }

        using var directory = new TestDirectory();
        FakeConfigurationStore store = CreateInitialStore();
        CrashCaptureReceiptStore receipts = new(Path.Combine(directory.Path, "Receipts"));
        ProtectedEvidenceHelper helper = CreateConfigurationHelper(directory.Path, store);
        using PCCrashDiagnosticCoordinator coordinator = CreateCoordinator(directory.Path, store, receipts, helper);
        DiagnosticOperationResultV3 report = BoundReport(directory.Path, UnprotectedTarget());
        string werRoot = Path.Combine(directory.Path, "WerDumps");
        WerLocalDumpPlan werPlan = CreateWerPlan(store, werRoot, UnprotectedTarget());

        await Assert.ThrowsAsync<NotSupportedException>(() =>
            coordinator.ApplyWerLocalDumpPlanAsync(report, werPlan));

        CrashCapturePlan embedded = CreateAutomaticPlan(store) with
        {
            WerLocalDumpPlan = werPlan,
            TargetProfile = report.Package.Report.TargetProfile
        };
        CrashCapturePreparationResult result = await coordinator.PrepareCrashCaptureAsync(report, embedded);

        Assert.False(result.Succeeded);
        Assert.Contains("not enabled", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, store.WriteCount);
        Assert.Equal(0, store.WerWriteCount);
    }

    [Fact]
    public async Task PersistedReceiptDiscoverySurvivesCoordinatorRestartAndRestoresLatest()
    {
        using var directory = new TestDirectory();
        string receiptRoot = Path.Combine(directory.Path, "Receipts");
        FakeConfigurationStore store = CreateInitialStore();
        CrashCaptureReceiptStore receipts = new(receiptRoot);
        ProtectedEvidenceHelper helper = new(
            Path.Combine(directory.Path, "Staging"),
            TestRoots(directory.Path),
            _ => long.MaxValue,
            () => false,
            store,
            receipts,
            TimeProvider.System,
            Path.Combine(directory.Path, "WerDumps"));
        DiagnosticOperationResultV3 report = BoundReport(directory.Path);
        using (PCCrashDiagnosticCoordinator first = CreateCoordinator(directory.Path, store, receipts, helper))
        {
            CrashCapturePlan preview = await first.PreviewCrashCapturePreparationAsync(report);
            CrashCapturePreparationResult applied = await first.PrepareCrashCaptureAsync(report, preview);
            Assert.True(applied.Succeeded, applied.Message);
        }

        File.WriteAllText(Path.Combine(receiptRoot, new string('f', 32) + ".crash.json"), "{malformed");
        using PCCrashDiagnosticCoordinator restarted = CreateCoordinator(directory.Path, store, receipts, helper);
        RestorableConfigurationReceipts discovery = restarted.DiscoverRestorableConfigurationReceipts();

        Assert.NotNull(discovery.CrashCaptureReceipt);
        Assert.NotEmpty(discovery.Warnings);
        CrashCapturePreparationResult restored = await restarted.RestoreLatestCrashCaptureAsync();
        Assert.True(restored.Succeeded, restored.Message);
        Assert.Null(restarted.DiscoverRestorableConfigurationReceipts().CrashCaptureReceipt);
    }

    private static CrashCapturePlan CreateAutomaticPlan(FakeConfigurationStore store)
    {
        var desired = new Dictionary<CrashCaptureSetting, StoredConfigurationValue>
        {
            [CrashCaptureSetting.CrashDumpEnabled] = new(true, "7", (int)Microsoft.Win32.RegistryValueKind.DWord),
            [CrashCaptureSetting.FilterPages] = new(false, null),
            [CrashCaptureSetting.DumpFile] = new(true, @"%SystemRoot%\MEMORY.DMP", (int)Microsoft.Win32.RegistryValueKind.ExpandString),
            [CrashCaptureSetting.EventLogging] = new(true, "1", (int)Microsoft.Win32.RegistryValueKind.DWord),
            [CrashCaptureSetting.OverwriteExistingDump] = new(true, "1", (int)Microsoft.Win32.RegistryValueKind.DWord)
        };
        if (CrashReadinessCollector.NeedsSystemManagedPageFileForAutomatic(store.Environment))
        {
            desired[CrashCaptureSetting.AutomaticManagedPagefile] = new(true, "true");
        }

        CrashCaptureChange[] changes = desired
            .Where(pair => store.ReadCrashSetting(pair.Key) != pair.Value)
            .Select(pair =>
            {
                StoredConfigurationValue previous = store.ReadCrashSetting(pair.Key);
                return new CrashCaptureChange(
                    pair.Key,
                    previous.Exists,
                    previous.Value,
                    pair.Value.Exists,
                    pair.Value.Value,
                    RequiresRestart: true,
                    pair.Key == CrashCaptureSetting.AutomaticManagedPagefile
                        ? store.ReadPageFileConfiguration()
                        : null,
                    previous.RegistryValueKind,
                    pair.Value.RegistryValueKind);
            })
            .ToArray();
        return new CrashCapturePlan(
            1,
            new string('c', 32),
            "test-session",
            new string('a', 64),
            Now,
            Now.AddMinutes(10),
            CrashCapturePreset.AutomaticMemoryDump,
            changes,
            ReadyReadiness(),
            RequiresElevation: true,
            RequiresRestart: true);
    }

    private static WerLocalDumpPlan CreateWerPlan(
        FakeConfigurationStore store,
        string werRoot,
        TargetProfile target,
        string executable = "PccdSyntheticTarget.exe")
    {
        WerConfigurationSnapshot previous = store.ReadWerSettings(executable);
        return new WerLocalDumpPlan(
            1,
            new string('d', 32),
            "test-session",
            new string('a', 64),
            Now,
            Now.AddMinutes(10),
            executable,
            previous.KeyExists,
            previous.DumpType.Exists,
            null,
            previous.DumpCount.Exists,
            null,
            previous.DumpFolder.Exists,
            previous.DumpFolder.Value,
            2,
            2,
            ProtectedEvidenceHelper.ApprovedWerDumpFolder(werRoot, executable),
            target);
    }

    private static ProtectedEvidenceRequest ConfigurationRequest(
        ProtectedEvidenceOperation operation,
        CrashCapturePlan? plan = null,
        WerLocalDumpPlan? werPlan = null,
        string? receiptId = null) => new(
            operation,
            null,
            null,
            null,
            null,
            false,
            false,
            false,
            CrashCapturePlan: plan,
            WerLocalDumpPlan: werPlan,
            ConfigurationReceiptId: receiptId);

    private static ProtectedEvidenceHelper CreateConfigurationHelper(
        string root,
        FakeConfigurationStore store,
        string suffix = "default",
        string? werRoot = null,
        Func<string, IReadOnlyList<WerProcessIdentity>>? matchingProcessIdentities = null) => new(
            Path.Combine(root, "Staging-" + suffix),
            TestRoots(root),
            _ => long.MaxValue,
            () => false,
            store,
            new CrashCaptureReceiptStore(Path.Combine(root, "Receipts-" + suffix)),
            new FixedTimeProvider(Now),
            werRoot ?? Path.Combine(root, "WerDumps-" + suffix),
            matchingProcessIdentities ?? (_ => [EligibleWerProcess()]));

    private static WerProcessIdentity EligibleWerProcess(
        int sessionId = 1,
        bool elevated = false,
        string? ownerSid = null) => new(
        sessionId,
        ownerSid ?? (System.Security.Principal.WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("The test user SID was unavailable.")).Value,
        elevated);

    private static ProtectedEvidenceRoots TestRoots(string root) => new(
        Path.Combine(root, "Windows", "MEMORY.DMP"),
        Path.Combine(root, "Windows", "Minidump"),
        Path.Combine(root, "Windows", "LiveKernelReports"));

    private static FakeConfigurationStore CreateInitialStore()
    {
        const long gib = 1024L * 1024 * 1024;
        var store = new FakeConfigurationStore
        {
            Environment = new CrashCaptureEnvironmentSnapshot(
                false,
                true,
                1 * gib,
                8 * gib,
                null,
                null,
                null,
                new PageFileRuntimeSnapshot(false, 1, 8 * gib, Now.AddHours(-2), 32 * gib))
        };
        store.PageFileConfiguration = new PageFileConfigurationSnapshot(
            true,
            false,
            true,
            [@"C:\pagefile.sys 1024 8192"]);
        store.Set(CrashCaptureSetting.CrashDumpEnabled, true, "3");
        store.Set(CrashCaptureSetting.FilterPages, true, "1");
        store.Set(CrashCaptureSetting.DumpFile, true, @"D:\Old\MEMORY.DMP");
        store.Set(CrashCaptureSetting.MinidumpDirectory, true, @"D:\Old\Minidump");
        store.Set(CrashCaptureSetting.EventLogging, true, "0");
        store.Set(CrashCaptureSetting.OverwriteExistingDump, true, "0");
        store.Set(CrashCaptureSetting.AutomaticManagedPagefile, true, "false");
        return store;
    }

    private static Dictionary<string, object?> AutomaticCrashValues() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["CrashDumpEnabled"] = 7,
        ["FilterPages"] = 0,
        ["LogEvent"] = 1,
        ["AutoReboot"] = 1,
        ["Overwrite"] = 1,
        ["AlwaysKeepMemoryDump"] = 0,
        ["DumpFile"] = @"%SystemRoot%\MEMORY.DMP",
        ["MinidumpDir"] = @"%SystemRoot%\Minidump"
    };

    private static PageFileRuntimeSnapshot ReadyRuntime()
    {
        const long gib = 1024L * 1024 * 1024;
        return new PageFileRuntimeSnapshot(true, 1, 32 * gib, Now.AddHours(-2), 32 * gib);
    }

    private static DestinationCapacity ReadyDestination()
    {
        const long gib = 1024L * 1024 * 1024;
        return new DestinationCapacity(true, 100 * gib, 200 * gib);
    }

    private static CrashReadiness ReadyReadiness() => new(
        Now,
        CrashDumpMode.AutomaticMemory,
        7,
        true,
        true,
        true,
        false,
        false,
        "%SystemRoot%\\MEMORY.DMP",
        "%SystemRoot%\\Minidump",
        1,
        true,
        100,
        200,
        CrashReadinessState.Ready,
        "Ready.",
        ActivationState: CrashCaptureActivationState.Active);

    private static TargetProfile UnprotectedTarget() => new(
        "synthetic-target",
        "Synthetic target",
        ["PccdSyntheticTarget"],
        [],
        ["PccdSyntheticTarget"],
        ["PccdSyntheticTarget"],
        ["PccdSyntheticTarget"],
        "Synthetic",
        BlockSensitiveOperationsWhileRunning: false,
        TargetPrivacyRules.Strict);

    private static DiagnosticOperationResultV3 BoundReport(string root, TargetProfile? targetProfile = null)
    {
        var report = new DiagnosticReportV3(
            3,
            PCCrashDiagnosticCoordinator.ToolVersion,
            PCCrashDiagnosticCoordinator.ProductName,
            "test-session",
            DiagnosticMode.Retrospective,
            Now.AddMinutes(-1),
            Now,
            "Test",
            null,
            targetProfile,
            null,
            null,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            ReadyReadiness(),
            new DumpInventory([], []),
            null,
            null,
            null,
            null,
            "Test report.");
        return new DiagnosticOperationResultV3(
            new ReportPackageV3(
                report,
                Path.Combine(root, "Sessions", "test-session"),
                Path.Combine(root, "Reports", "test.zip"),
                Path.Combine(root, "Reports", "test.sha256"),
                new string('a', 64)),
            [],
            false,
            []);
    }

    private static PCCrashDiagnosticCoordinator CreateCoordinator(
        string root,
        FakeConfigurationStore store,
        CrashCaptureReceiptStore receipts,
        ProtectedEvidenceHelper helper) => new(
        root,
        (_, _) => Task.CompletedTask,
        new DirectHelperClient(helper),
        helper,
        new ElevatedHelperRequestStore(Path.Combine(root, "Requests")),
        () => false,
        _ => false,
        null,
        store,
        receipts,
        _ => Task.FromResult(new CrashReadinessCollection(ReadyReadiness(), [])));

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => utcNow;
    }

    private sealed class DirectHelperClient(ProtectedEvidenceHelper helper) : IElevatedHelperClient
    {
        public Task<ProtectedEvidenceResponse> ExecuteAsync(
            ProtectedEvidenceRequest request,
            Func<bool> isProtectedTargetRunning,
            TimeSpan timeout,
            CancellationToken cancellationToken = default) => helper.ExecuteAsync(request, cancellationToken);
    }

    private sealed class FakeConfigurationStore : ICrashCaptureConfigurationStore
    {
        private readonly Dictionary<CrashCaptureSetting, StoredConfigurationValue> _settings = [];
        private readonly Dictionary<string, WerConfigurationSnapshot> _wer = new(StringComparer.OrdinalIgnoreCase);

        public CrashCaptureEnvironmentSnapshot Environment { get; set; } = new(
            false,
            false,
            null,
            null,
            null,
            null,
            null,
            new PageFileRuntimeSnapshot(false, 0, null, Now.AddHours(-2), 32L * 1024 * 1024 * 1024));

        public CrashCaptureSetting? FailSetting { get; set; }

        public int FailuresRemaining { get; set; }

        public CrashCaptureSetting? DiscardWriteSetting { get; set; }

        public int DiscardWritesRemaining { get; set; }

        public CrashCaptureSetting? ThrowAfterWriteSetting { get; set; }

        public int ThrowAfterWritesRemaining { get; set; }

        public Action<CrashCaptureSetting>? AfterCrashWrite { get; set; }

        public int ThrowAfterWerWritesRemaining { get; set; }

        public bool PreserveWerKeyWhenRestoringAbsentOwnedValues { get; set; }

        public PageFileConfigurationSnapshot PageFileConfiguration { get; set; } = new(
            true,
            false,
            true,
            [@"C:\pagefile.sys 0 0"]);

        public Exception? ReadPageFileConfigurationFailure { get; set; }

        public int WriteCount { get; private set; }

        public int WerWriteCount { get; private set; }

        public void Set(CrashCaptureSetting setting, bool exists, string? value, int? registryValueKind = null)
        {
            int? inferredKind = !exists || setting == CrashCaptureSetting.AutomaticManagedPagefile
                ? null
                : registryValueKind ?? (setting is CrashCaptureSetting.DumpFile or CrashCaptureSetting.MinidumpDirectory
                    ? (int)Microsoft.Win32.RegistryValueKind.ExpandString
                    : (int)Microsoft.Win32.RegistryValueKind.DWord);
            _settings[setting] = new StoredConfigurationValue(exists, value, inferredKind);
        }

        public StoredConfigurationValue ReadCrashSetting(CrashCaptureSetting setting) =>
            _settings.TryGetValue(setting, out StoredConfigurationValue? value)
                ? value
                : new StoredConfigurationValue(false, null);

        public void WriteCrashSetting(CrashCaptureSetting setting, StoredConfigurationValue value)
        {
            WriteCount++;
            if (FailSetting == setting && FailuresRemaining-- > 0)
            {
                throw new IOException("Synthetic write failure.");
            }

            if (DiscardWriteSetting == setting && DiscardWritesRemaining-- > 0)
            {
                return;
            }

            _settings[setting] = value;
            if (setting == CrashCaptureSetting.AutomaticManagedPagefile &&
                value.Exists && bool.TryParse(value.Value, out bool automatic))
            {
                PageFileConfiguration = PageFileConfiguration with
                {
                    AutomaticManagementStateKnown = true,
                    AutomaticManagementEnabled = automatic
                };
            }

            AfterCrashWrite?.Invoke(setting);
            if (ThrowAfterWriteSetting == setting && ThrowAfterWritesRemaining-- > 0)
            {
                throw new IOException("Synthetic post-commit write failure.");
            }
        }

        public WerConfigurationSnapshot ReadWerSettings(string executableName) =>
            _wer.TryGetValue(executableName, out WerConfigurationSnapshot? value)
                ? value
                : new WerConfigurationSnapshot(
                    false,
                    new StoredConfigurationValue(false, null),
                    new StoredConfigurationValue(false, null),
                    new StoredConfigurationValue(false, null));

        public void SetWer(string executableName, WerConfigurationSnapshot value) =>
            _wer[executableName] = value;

        public void WriteWerSettings(string executableName, WerConfigurationSnapshot value)
        {
            WerWriteCount++;
            if (PreserveWerKeyWhenRestoringAbsentOwnedValues &&
                !value.KeyExists && !value.DumpType.Exists &&
                !value.DumpCount.Exists && !value.DumpFolder.Exists)
            {
                value = value with { KeyExists = true };
            }

            _wer[executableName] = value;
            if (ThrowAfterWerWritesRemaining-- > 0)
            {
                throw new IOException("Synthetic post-commit WER write failure.");
            }
        }

        public PageFileRuntimeSnapshot ReadPageFileRuntime() => Environment.RuntimePageFiles;

        public PageFileConfigurationSnapshot ReadPageFileConfiguration()
        {
            if (ReadPageFileConfigurationFailure is not null)
            {
                throw ReadPageFileConfigurationFailure;
            }

            return PageFileConfiguration;
        }

        public void RestorePageFileConfiguration(PageFileConfigurationSnapshot snapshot)
        {
            WriteCount++;
            PageFileConfiguration = snapshot;
            _settings[CrashCaptureSetting.AutomaticManagedPagefile] = new StoredConfigurationValue(
                true,
                snapshot.AutomaticManagementEnabled ? "true" : "false");
        }

        public CrashCaptureEnvironmentSnapshot ReadEnvironment() => Environment;
    }
}
