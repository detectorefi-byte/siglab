# SigLab

`SigLab` is a Visual Studio 2022 C++ console tool for PE Authenticode
experiments in an isolated lab. It grafts a donor's Authenticode certificate
table onto a PE file and, when launched as **Administrator**, automatically
installs the lab registry bypass (SIP all 19 + FinalPolicy) and verifies the
result in a fresh process.

> **Authorised VM / lab testing only.** The automatic bypass writes to
> `HKLM` and persists until you run `SigLab.exe --clean`. Take a VM
> snapshot before testing.

---

## Quick start

1. Build `Release | x64`.
2. Run `SigLab.exe`. It requests Administrator rights through UAC
   automatically; approve the prompt.
3. Paste the target path (or drag & drop the file onto the console), then press
   Enter.

That is the only input. One run signs the file, installs the registry bypass,
probes Code Integrity, and verifies the result in a fresh process.

```bat
SigLab.exe C:\lab\sample.dll
```

The default console output is intentionally minimal:

```text
[*] Initializing...
[*] Signing the file...
[+] Successful.
```

File details, donor selection, probe output, registry diagnostics and the
detailed verification result are hidden. Use `--verbose` when you need them.

The command succeeds only when the fresh-process verification returns `VALID`
(exit code `0`).

To keep the original file untouched, add `--copy`:

```bat
SigLab.exe --copy C:\lab\sample.dll
```

With Administrator rights the tool then:

- grafts the donor certificate table,
- installs **SIP bypass for all 19 types** (64-bit and 32-bit registry views),
- installs the **FinalPolicy** bypass (64-bit and 32-bit views),
- probes Code Integrity / HVCI / Smart App Control,
- verifies the signed file in a **fresh child process**.

Expected result (default quiet mode):

```text
  [+] Successful.
```

With `--verbose` the detailed result is:

```text
  Verify : VALID (fresh process)
```

Without Administrator rights:

- signing still works,
- the registry bypass is skipped,
- the default output ends with:

```text
  [-] Signature did not verify.
```

That is the normal grafted-signature result until the bypass is installed.

---

## Output modes

| Mode | Output |
|---|---|
| default one-shot | banner, path prompt, `Initializing`, `Signing the file`, `Successful` |
| `--verbose` | full file facts, donor, probe, registry and verification details |
| `--probe` | standalone Code Integrity / HVCI / SAC report |
| `--advanced` | full manual toolkit menu with diagnostics |

Failures print a short reason; `--verbose` adds the detailed error. Exit codes
are unchanged: `0` = VALID, `2` = HashMismatch, `3` = other error.

---

## One-shot mode (default)

```bat
SigLab.exe [--copy] [--verbose] [--donor <signed exe>] [<file>]
```

The pipeline runs without any further prompts:

```text
1. inspect the target PE
2. pick a signed donor (Edge / Chrome / Visual Studio) unless --donor is given
3. graft the donor Authenticode signature
4. install SIP (all 19) + FinalPolicy bypass          (Administrator only)
5. probe Code Integrity / HVCI / Smart App Control       (hidden by default)
6. verify in a fresh process
7. print a short result and exit code
```

Exit codes: `0` = VALID, `2` = HashMismatch, `3` = other error.

The only prompt is the target path when it is not passed on the command line.
Pass `--verbose` to see the full pipeline and verification details.

## Advanced menu

The full toolkit is still available behind `--advanced` (or `--menu`):

```text
[1]  Sign / graft signature
[2]  Bypass / registry
[3]  Embed payload in signature
[4]  Extract payload from signature
[5]  SIP-Exec implant
[6]  Probe Code Integrity
[7]  Clean / restore
[0]  Exit
```

`[1]` still applies the bypass automatically after a successful signature
graft. `[2]`, `[5]` and `[7]` are the manual registry controls.

---

## Signing flow

### In-place vs copy

One-shot mode signs **in place** by default:

```bat
SigLab.exe C:\lab\sample.dll
```

Use `--copy` to write `<name>_signed<ext>` and leave the original untouched.
In the advanced menu the choice is:

```text
[1] Modify the original file in place     default
[2] Create a signed copy
```

- **In place** overwrites the target. A temporary backup is created in `%TEMP%`
  and deleted after success. If signing or metadata cloning fails, the backup is
  restored.
- **Copy** writes `<name>_signed<ext>` and leaves the original untouched. If the
  name exists, the tool uses `<name>_signed2<ext>`, `<name>_signed3<ext>`, ...

### Donor choice

One-shot mode selects the donor automatically. Override it with `--donor`:

```bat
SigLab.exe --donor "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" sample.dll
```

In the advanced menu:

```text
[1] Auto-select donor (Edge / Chrome / Visual Studio)     default
[2] Enter donor path manually
```

Auto-detect checks:

1. Microsoft Edge (`msedge.exe`)
2. Google Chrome (`chrome.exe`)
3. Visual Studio 2022/2019 (`devenv.exe`)

If none is found, the tool asks for a donor path.

> **Catalog-signed files cannot be donors.** `notepad.exe`, `cmd.exe`,
> `explorer.exe`, and many drivers are signed by a catalog, not by an embedded
> certificate table. PowerShell may show them as `Valid`, but there is nothing
> to copy. Use Edge, Chrome, Visual Studio, or another third-party signed file.

### Clone metadata

Only offered in the advanced menu (`--advanced`). It is off in one-shot mode.
When enabled it copies the donor's version info, icon groups, icons, and
manifest. Some donors (for example Edge) fail resource commit with Win32 error
13; the tool then restores the original and aborts. This is normal.

---

## What the automatic bypass does

When the process is elevated, after a successful signature graft:

```text
SIP bypass            all 19 SIP GUIDs, 64-bit + 32-bit registry views
FinalPolicy           SoftpubCleanup, 64-bit + 32-bit views
Fresh-process verify  SigLab.exe --verify-quiet <file>
```

The 19 SIP types are the 17 standard types plus:

- Smart App Control (SAC)
- AppX Extensions (Windows 11)

The bypass makes `WinVerifyTrust` return success for the grafted signature.
It is system-wide and survives reboots until cleaned.

### If verification still fails

Default quiet mode prints:

```text
[-] Signature did not verify.
```

`--verbose` shows the detailed status:

```text
Verify : HashMismatch (fresh process)
```

Possible causes:

- the tool is not running as Administrator,
- HVCI / Memory Integrity or Smart App Control blocks the bypass,
- a reboot / logoff is needed for the policy change to be picked up,
- the target is a 32-bit process and a policy view was not written (both views
  are written by this build).

Use `SigLab.exe --probe` (or `[6] Probe Code Integrity` in `--advanced`) to
inspect CI, HVCI, and SAC state, plus the live PE SIP and FinalPolicy values.
After a successful auto-bypass those should read `ntdll.dll!DbgUiContinue` and
`WINTRUST.DLL!SoftpubCleanup`. Run `SigLab.exe --clean` to remove the bypass.

### Windows 10 notes

- Windows 10 has no Smart App Control, so `--probe` shows `Smart App Control: no`.
- `HVCI (Memory Integrity): no` means HVCI is **off**, which is the desired state
  for this test. `CI Enabled: YES` is the normal kernel CI state.
- The ESD SIP key (`{9F3053C5-439D-4BF7-8A77-04F0450A1D9F}`) is owned by
  SYSTEM / TrustedInstaller and cannot be written by an elevated Administrator.
  SigLab treats it as skipped and continues; the PE, PowerShell, MSI and other
  types are still bypassed, and PE verification is unaffected. An 18/19 active
  count is normal on such a system. This detail is only shown with `--verbose`.

### Why Windows may still show "This digital signature is not valid"

A grafted signature is a byte copy of the donor's PKCS#7 blob. The digest inside
it belongs to the donor file, so a raw cryptographic check always reports
`TRUST_E_BAD_DIGEST`. The registry bypass makes `WinVerifyTrust` return success;
that is what PowerShell, `signtool`, UAC and SmartScreen use.

Two things can still make the file Properties page look wrong:

1. **Explorer cache / old process.** `explorer.exe` caches the SIP provider the
   first time it verifies a signature. After installing the bypass you must log
   off and back in (or restart Explorer) before *Properties -> Digital
   Signatures* reflects the new state. A fresh `powershell` window is enough
   for `Get-AuthenticodeSignature`.
2. **Smart App Control / HVCI.** SAC (`0x2000`) and Memory Integrity (`0x100`)
   enforce their own checks. Turn them off in Windows Security, reboot, and
   retry. `--probe` shows both flags.

SigLab now asks for UAC automatically, so the bypass is installed even if you
start it by double-clicking. Use `--no-elevate` to disable that (the bypass is
then skipped and verification shows `HashMismatch`).

---

## Registry tools

### `[2] Bypass / registry`

```text
[1] SIP bypass - default (PE, PowerShell, MSI)
[2] SIP bypass - all 17 standard types
[3] SIP bypass - all 19 (includes SAC + AppX extensions)
[4] SIP bypass - custom type list
[5] FinalPolicy bypass (SoftpubCleanup)
[6] Custom trust provider
[0] Back
```

All of these require Administrator.

### `[5] SIP-Exec implant`

```text
[1] Install implant DLL
[2] Remove implant
[3] List registered triggers
[0] Back
```

Install registers a DLL under:

```text
HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllIsMyFileType2\<GUID>
```

with `Dll` and `FuncName=IsMyFileType2`. Aliases such as `pe`, `ps1`, `msi`,
`jscript`, `vbscript`, `wsf`, `appx`, `catalog`, and `sac` are supported, as is
a raw GUID.

### `[6] Probe Code Integrity`

Read-only. Shows the CI flags, HVCI, Smart App Control, and the live values for:

```text
PE SIP        64-bit / 32-bit
FinalPolicy   64-bit / 32-bit
```

A bypassed system shows `ntdll.dll!DbgUiContinue` for the PE SIP and
`WINTRUST.DLL!SoftpubCleanup` for FinalPolicy. Defaults show
`WINTRUST.DLL!CryptSIPVerifyIndirectData` and
`WINTRUST.DLL!SoftpubAuthenticode`.

### `[7] Clean / restore`

```text
[1] Restore all SIP keys (19)
[2] Restore FinalPolicy
[3] Remove a custom trust provider
[4] Restore everything (SIP + FinalPolicy)
[0] Back
```

`[4]` restores the correct per-type default SIP provider for each GUID (MSI,
PowerShell, AppX, scripts, etc.), removes the legacy
`WOW6432Node\WOW6432Node` keys created by the upstream 32-bit path bug, and
removes the stale AppX Extensions GUID.

---

## How signing works

A PE file stores its signature in a certificate table. The optional header's
`Security` data directory (index 4) points to it:

```text
DataDirectory[4] -> file offset + size of the WIN_CERTIFICATE table
```

For each target the tool:

1. Copies the target (or uses the target itself for in-place mode).
2. Reads the donor's `WIN_CERTIFICATE` table.
3. Appends the donor table to the target at an 8-byte boundary.
4. Repoints the target's `Security` directory at the appended table.

```text
donor.exe  ── copy certificate table ──┐
                                       ▼
target.dll ── copy / in place ──► target.dll
                                  + donor certificate table
                                  + patched Security directory
```

The result carries a real certificate table and the donor's publisher name.
But `WinVerifyTrust` hashes the target bytes and compares them with the digest
inside the donor's signature:

```text
TRUST_E_BAD_DIGEST (0x80096010)  ->  HashMismatch
```

The registry bypass is what turns that into `VALID`.

---

## Build

### Visual Studio

1. Open `SigLab.sln` in Visual Studio 2022.
2. Select `Release` and `x64`.
3. Build the solution (`Ctrl+Shift+B`).

Output:

```text
bin\x64\Release\SigLab.exe
```

### Command line

```bat
build.bat
```

or:

```bat
"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" ^
  SigLab.sln /p:Configuration=Release /p:Platform=x64 /m
```

Requirements: Visual Studio 2022 with **Desktop development with C++**.
The project links `wintrust.lib`, `crypt32.lib`, `advapi32.lib`, and
`shell32.lib` from the Windows SDK.

The Release configuration links the C runtime **statically** (`/MT`), so
`bin\x64\Release\SigLab.exe` is a single self-contained file. It depends only
on system DLLs (`KERNEL32`, `ADVAPI32`, `CRYPT32`, `WINTRUST`) and runs on a
clean Windows VM without the Visual C++ Redistributable.

> Do **not** copy the `Debug` build into the VM. The Debug configuration uses
> the debug CRT (`/MDd`) and needs `ucrtbased.dll`, `msvcp140d.dll`, and
> `vcruntime140d.dll`, which are not part of any redistributable package.

---

## Run

```bat
SigLab.exe
```

For automatic bypass, run it from an **Administrator** console or use
right-click -> **Run as administrator**.

### Command-line switches

```bat
SigLab.exe <file>            one-shot: sign + bypass + probe + verify
SigLab.exe                   ask for the file path, then the same
SigLab.exe --copy <file>     write <name>_signed instead of in place
SigLab.exe --donor <exe>     use a specific donor
SigLab.exe --clean           restore SIP + FinalPolicy
SigLab.exe --probe           read-only Code Integrity / bypass state
SigLab.exe --advanced        full manual toolkit menu
SigLab.exe --no-elevate      never ask for UAC (bypass skipped)
SigLab.exe --verify <file>   verify only
SigLab.exe --banner
SigLab.exe --help
```

`--verify` exits with:

```text
0  VALID
2  HashMismatch
3  other / not a PE
```

This is also the command used internally by the fresh-process verifier.

---

## VM test

1. Take a VM snapshot.
2. Copy `bin\x64\Release\SigLab.exe` into the VM. Nothing else is needed; the
   Release build is statically linked and has no VC++ redistributable
   requirement.
3. Run `SigLab.exe` and approve the UAC prompt.
4. Paste a harmless target path, for example a copy of `SigLab.exe` renamed
   to `sample.dll`, and press Enter.
5. Expected output:

```text
  [+] Original file modified in place.
  [*] Applying automatic lab bypass...
  [+] SIP bypass installed (all 19, 64-bit + 32-bit).
  [+] FinalPolicy bypass installed (64-bit + 32-bit).
  [*] Verifying in a fresh process...

  File   : C:\...\sample.dll  (modified in place)
  Signer : Microsoft Corporation
  Verify : VALID (fresh process)
```

6. Check from PowerShell:

```powershell
Get-AuthenticodeSignature .\sample.dll | Format-List Status, SignatureType, SignerCertificate
# Status        : Valid
# SignatureType : Authenticode
# Signer        : CN=Microsoft Corporation, ...
```

7. Clean up before reverting the snapshot:

```bat
SigLab.exe --clean
```

or in the advanced menu:

```text
[7] Clean / restore -> [4] Restore everything
```

Then reboot / log off if needed.

### If you do not run as Administrator

```text
Bypass : skipped (not Administrator)
...
Verify : HashMismatch
```

The signature is still grafted; only the registry bypass is missing. Start
SigLab normally (it asks for UAC) or use `--no-elevate` deliberately.

---

## Files

```text
SigLab/
├── SigLab.sln
├── SigLab.vcxproj
├── SigLab.vcxproj.filters
├── build.bat
├── src/
│   ├── cli.cpp              banner, one-shot pipeline, advanced menu,
│   │                        auto bypass, embed/extract, SIP-Exec, probe, clean
│   ├── pe_signature.h       PE parsing, signature graft, signer lookup,
│   │                        WinVerifyTrust, CI probe
│   ├── sip_registry.h       SIP/FinalPolicy registry bypass, cleanup, SIP tables
│   └── pkcs7_payload.h      PKCS#7 payload embed/extract
└── README.md
```

Source notes for this build:

- removed the duplicate `WIN_CERTIFICATE` declaration that conflicts with
  `<wintrust.h>`,
- corrected the 32-bit SIP registry path (`KEY_WOW64_32KEY` plus the logical
  `SOFTWARE\Microsoft\...` path, instead of double-nesting `WOW6432Node`),
- corrected the Windows 11 AppX Extensions GUID,
- added 32-bit views for FinalPolicy,
- restores per-type SIP defaults during Clean and removes legacy nested/stale keys,
- added fresh-process verification.

---

## Notes and limits

- The target must be a PE file (EXE/DLL/SYS). Scripts and documents are not
  handled.
- The donor must have an embedded PKCS#7 signature, not only a catalog entry.
- The grafted signature is a byte-copy of the donor's signature. It is not a new
  CA-issued signature and fails digest validation without the bypass.
- In-place mode writes the target directly. Keep a VM snapshot.
- The automatic bypass writes `HKLM` and persists. Run `SigLab.exe --clean` to
  restore it.
- No network access is used by SigLab.
- The tool does not clean up automatically on exit; run `SigLab.exe --clean`.
