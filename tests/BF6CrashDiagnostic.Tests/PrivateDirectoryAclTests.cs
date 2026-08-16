using System.Security.AccessControl;
using System.Security.Principal;
using BF6CrashDiagnostic.Core.Analysis;

namespace BF6CrashDiagnostic.Tests;

public sealed class PrivateDirectoryAclTests
{
    [Fact]
    public void EnsureRestrictedToCurrentUserAndSystem_ReplacesExistingExplicitDaclExactly()
    {
        using var directoryRoot = new TestDirectory();
        string path = Path.Combine(directoryRoot.Path, "existing-private-directory");
        Directory.CreateDirectory(path);
        var directory = new DirectoryInfo(path);
        DirectorySecurity planted = directory.GetAccessControl(AccessControlSections.Access);
        planted.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        RemoveExplicitRules(planted);

        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        var guests = new SecurityIdentifier(WellKnownSidType.BuiltinGuestsSid, null);
        planted.AddAccessRule(new FileSystemAccessRule(
            everyone,
            FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        planted.AddAccessRule(new FileSystemAccessRule(
            guests,
            FileSystemRights.WriteData,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Deny));
        directory.SetAccessControl(planted);

        PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(path);

        DirectorySecurity restricted = directory.GetAccessControl(AccessControlSections.Access);
        FileSystemAccessRule[] explicitRules = restricted
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();
        SecurityIdentifier currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("The current Windows user SID was unavailable.");
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        HashSet<SecurityIdentifier> expectedPrincipals = [currentUser, system];

        Assert.True(restricted.AreAccessRulesProtected);
        Assert.Equal(expectedPrincipals.Count, explicitRules.Length);
        Assert.DoesNotContain(explicitRules, rule => rule.IsInherited);
        Assert.DoesNotContain(explicitRules, rule => rule.IdentityReference.Equals(everyone));
        Assert.DoesNotContain(explicitRules, rule => rule.IdentityReference.Equals(guests));
        Assert.All(explicitRules, rule =>
        {
            SecurityIdentifier identity = Assert.IsType<SecurityIdentifier>(rule.IdentityReference);
            Assert.Contains(identity, expectedPrincipals);
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            Assert.Equal(
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                rule.InheritanceFlags);
            Assert.Equal(PropagationFlags.None, rule.PropagationFlags);
        });
        Assert.All(expectedPrincipals, principal =>
            Assert.Single(explicitRules, rule => rule.IdentityReference.Equals(principal)));
    }

    private static void RemoveExplicitRules(DirectorySecurity security)
    {
        FileSystemAccessRule[] rules = security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .ToArray();
        foreach (FileSystemAccessRule rule in rules)
        {
            security.RemoveAccessRuleSpecific(rule);
        }
    }
}
