using BF6CrashDiagnostic.App.Models;

namespace BF6CrashDiagnostic.App.Services;

internal interface IUserInteractionService
{
    void CopyText(string text);
    string? ChooseExecutablePath();
    IReadOnlyList<UiRunningProcess> GetRunningProcesses();
    string? ChooseExportPath(string sourcePath);
    void OpenFolder(string folderPath);
    bool ConfirmDumpPackaging();
    UiProtectedDumpConsent? ConfirmProtectedDumpCopy(UiDumpChoice dump, string operationName);
    bool ConfirmProtectedEvidenceRetry(UiProtectedEvidenceSourceChoice source);
    bool ConfirmLegacyReportImport(int reportCount);
    bool ConfirmMicrosoftSymbolDownload();
    bool ConfirmCrashPreparation(UiCrashPreparationPreview preview);
    bool ConfirmCrashPreparationRestore();
    bool ConfirmPerAppCrashCaptureRestore(string targetName);
    bool ConfirmOrdinaryAppForCrashCapture(string targetName);
    void ShowMessage(string title, string message, bool isError = false);
}
