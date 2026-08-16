# Third-party notices

PC Crash Diagnostic source is licensed under the project [MIT License](LICENSE). The self-contained Windows release embeds .NET runtime, Windows Desktop Runtime, and WPF components; those embedded components are not all governed by the project's MIT License.

Microsoft's [.NET license information](https://github.com/dotnet/core/blob/main/license-information.md) and [.NET on Windows license mapping](https://github.com/dotnet/core/blob/main/license-information-windows.md) state that:

- .NET source and most .NET/WPF files are MIT-licensed;
- `coreclr.dll` and the .NET runtime embedded in Windows single-file applications are under the Microsoft .NET Library License;
- `PresentationNative_cor3.dll`, `vcruntime140_cor3.dll`, and `wpfgfx_cor3.dll` are under the Microsoft .NET Library License; and
- `D3DCompiler_47_cor3.dll` is under the Microsoft Windows SDK License.

Each runtime ZIP therefore carries these authoritative files under `licenses/`:

- `DOTNET-LIBRARY-LICENSE.txt` — license terms from the official Microsoft .NET SDK 10.0.302 Windows distribution, which carries .NET runtime 10.0.10; the [.NET SDK repository](https://github.com/dotnet/sdk) documents downloaded archive `LICENSE.txt` and `ThirdPartyNotices.txt` files as authoritative.
- `DOTNET-RUNTIME-MIT-LICENSE.txt` and `DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt` — [.NET Runtime v10.0.10](https://github.com/dotnet/runtime/tree/v10.0.10).
- `DOTNET-WPF-MIT-LICENSE.txt` and `DOTNET-WPF-THIRD-PARTY-NOTICES.txt` — [WPF v10.0.10](https://github.com/dotnet/wpf/tree/v10.0.10).
- `DOTNET-WINDOWS-LICENSE-INFORMATION.md` — Microsoft's [.NET on Windows binary-to-license mapping](https://github.com/dotnet/core/blob/main/license-information-windows.md).
- `WINDOWS-SDK-LICENSE.md` — Microsoft's [Windows SDK license terms](https://learn.microsoft.com/en-us/legal/windows-sdk/license).

Runtime library packages referenced by this repository include `System.Diagnostics.PerformanceCounter` 10.0.10 and `System.Management` 10.0.10. They are Microsoft .NET library packages distributed under MIT terms and are covered by the .NET Runtime license and notice files above.

Test-only packages, not required by the released application:

- xUnit.net and `xunit.runner.visualstudio` — Apache License 2.0: <https://github.com/xunit/xunit>
- Microsoft.NET.Test.Sdk — MIT: <https://github.com/microsoft/vstest>

The names Battlefield, Battlefield 6, Electronic Arts, AMD, Microsoft, Windows, and other marks belong to their respective owners. Their mention identifies compatibility or evidence sources and does not imply endorsement.

Contributors adding or updating a dependency must update this file and preserve the exact license and notice files required by that dependency. The release builder and verifier treat the listed runtime license payload as mandatory.
