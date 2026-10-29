# 🛡️ SigLab

> **⚠️ EDUCATIONAL & LAB USE ONLY.** SigLab is a security-research tool for studying Windows Authenticode internals in isolated virtual machines. **Do not run it on production systems, systems you do not own, or without explicit written authorisation.** See [Legal Notice](#-legal-notice).

![C++](https://img.shields.io/badge/C%2B%2B-17-blue?style=for-the-badge&logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6?style=for-the-badge&logo=windows)
![Toolset](https://img.shields.io/badge/VS2022-v143-purple?style=for-the-badge&logo=visual-studio)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Educational-orange?style=for-the-badge)

**SigLab** is an open-source C++ console toolkit designed to explore how Windows PE Authenticode signature verification works internally. It is built for security researchers, reverse engineers, and students who want to understand the PE certificate table, CryptoAPI SIP providers, and the `WinVerifyTrust` trust pipeline — all within an isolated lab VM.

SigLab is **not** a malware development tool or a signing bypass for production. It grafts a donor's PKCS#7 certificate table onto a target PE file, then demonstrates how registry-level SIP redirection affects `WinVerifyTrust`.

---

## 📑 Table of Contents
1. [⚠️ Educational Use Only](#-educational-use-only)
2. [What SigLab Demonstrates](#-what-siglab-demonstrates)
3. [Features](#-features)
4. [System Architecture](#️-system-architecture)
5. [Execution Flow (One-Shot)](#️-execution-flow-one-shot)
6. [How Signature Grafting Works](#-how-signature-grafting-works)
7. [Quick Start & Build](#-quick-start--build)
8. [Command-Line Reference](#-command-line-reference)
9. [Legal Notice](#️-legal-notice)

---

## ⚠️ Educational Use Only

This tool is published **for educational and authorised security-research purposes only**.

- ✅ **Allowed:** Authorised penetration testing, isolated VM labs, academic research, learning Windows internals.
- ❌ **Not allowed:** Malware development, bypassing security on systems you don't own, modifying signatures on third-party software, any use violating local or international law.

**You are solely responsible** for how you use this tool. The author accepts **no liability** for misuse, damage, or legal consequences. Using SigLab on systems you do not own is **illegal** under the CFAA, UK Computer Misuse Act, and equivalent laws worldwide.

**Before every test:**
1. Take a VM snapshot.
2. Confirm you own the target machine.
3. Run `SigLab.exe --clean` when finished.

---

## 🎓 What SigLab Demonstrates

SigLab is a teaching tool. Each run illustrates how Windows decides whether a binary is trusted.

| Concept | What you learn |
|---|---|
| **PE Certificate Table** | How `DataDirectory[4]` points to an embedded `WIN_CERTIFICATE` blob. |
| **PKCS#7 / CMS** | How an Authenticode signature is a CMS `SignedData` object with `signerInfos`. |
| **Digest Binding** | Why a byte-copied signature fails `TRUST_E_BAD_DIGEST` (the digest belongs to the donor). |
| **CryptoAPI SIP** | How `CryptSIPDllVerifyIndirectData` is dispatched per file type via the registry. |
| **FinalPolicy Provider** | How `WinVerifyTrust` ends in a `SoftpubAuthenticode` call. |
| **Code Integrity Flags** | How `SystemCodeIntegrityInformation` exposes HVCI, UMCI, and Smart App Control state. |

---

## ✨ Features

- 🔍 **PE Inspection** — Parses DOS/NT headers, validates `DataDirectory[4]`, detects existing signatures.
- 🧬 **Signature Grafting** — Copies a donor's `WIN_CERTIFICATE` table onto a target, 8-byte aligned, with `Security` directory repointing.
- 🗂️ **PKCS#7 Payload** — Hand-rolled ASN.1 DER parser for `unsignedAttrs`, with optional "camouflage" nesting.
- ⚙️ **SIP Bypass Installer** — Writes lab-only registry overrides for all 19 SIP types (64-bit and 32-bit views).
- 🛡️ **FinalPolicy Redirect** — Demonstrates redirecting `SoftpubAuthenticode` → `SoftpubCleanup`.
- 🧪 **Code Integrity Probe** — Read-only report of CI flags, HVCI, UMCI, Smart App Control.
- 🧾 **Fresh-Process Verifier** — Re-runs `WinVerifyTrust` in a child process to reflect policy changes.
- 🧹 **Clean / Restore** — Per-type SIP defaults, legacy-key removal, FinalPolicy restore.

---

## 🏗️ System Architecture

SigLab is highly modular. Here is how the source files interact:

```mermaid
graph TD
    CLI["cli.cpp"] --> PE["pe_signature.h"]
    CLI --> SIP["sip_registry.h"]
    CLI --> PKCS["pkcs7_payload.h"]
    PE -.-> WIN["wintrust.lib"]
    SIP -.-> REG["HKLM Registry"]
