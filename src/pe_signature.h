#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <winerror.h>
#include <wincrypt.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace pesign {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// PE inspection
// ---------------------------------------------------------------------------

struct PeInfo {
    bool valid = false;
    bool pe32plus = false;
    uint16_t machine = 0;
    uint64_t fileSize = 0;
    uint32_t certOffset = 0;      // Security directory VirtualAddress (file offset)
    uint32_t certSize = 0;        // Security directory Size
    uint64_t certDirEntryOffset = 0; // File offset of DataDirectory[4]
    std::wstring error;
};

inline bool ReadExact(std::ifstream& f, uint64_t offset, void* buffer, size_t size) {
    f.clear();
    f.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!f) return false;
    f.read(static_cast<char*>(buffer), static_cast<std::streamsize>(size));
    return f.gcount() == static_cast<std::streamsize>(size);
}

inline PeInfo InspectPe(const std::wstring& path) {
    PeInfo info;

    std::ifstream file(fs::path(path), std::ios::binary);
    if (!file) {
        info.error = L"cannot open file";
        return info;
    }

    file.seekg(0, std::ios::end);
    const std::streamoff end = file.tellg();
    if (end < 0) {
        info.error = L"cannot determine file size";
        return info;
    }
    info.fileSize = static_cast<uint64_t>(end);

    IMAGE_DOS_HEADER dos{};
    if (!ReadExact(file, 0, &dos, sizeof(dos))) {
        info.error = L"file is too small to contain a DOS header";
        return info;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        info.error = L"not a PE file (missing MZ header)";
        return info;
    }
    if (dos.e_lfanew <= 0 ||
        static_cast<uint64_t>(dos.e_lfanew) + 4 + sizeof(IMAGE_FILE_HEADER) > info.fileSize) {
        info.error = L"invalid DOS header (e_lfanew out of range)";
        return info;
    }

    const uint64_t ntOffset = static_cast<uint64_t>(dos.e_lfanew);
    uint32_t signature = 0;
    if (!ReadExact(file, ntOffset, &signature, sizeof(signature)) ||
        signature != IMAGE_NT_SIGNATURE) {
        info.error = L"not a PE file (missing PE signature)";
        return info;
    }

    IMAGE_FILE_HEADER fileHeader{};
    if (!ReadExact(file, ntOffset + 4, &fileHeader, sizeof(fileHeader))) {
        info.error = L"truncated COFF header";
        return info;
    }

    const uint64_t optionalOffset = ntOffset + 4 + sizeof(IMAGE_FILE_HEADER);
    uint16_t magic = 0;
    if (!ReadExact(file, optionalOffset, &magic, sizeof(magic))) {
        info.error = L"truncated optional header";
        return info;
    }

    uint32_t dataDirectoryOffset = 0;
    if (magic == 0x10B) { // PE32
        info.pe32plus = false;
        dataDirectoryOffset = 96;
    } else if (magic == 0x20B) { // PE32+
        info.pe32plus = true;
        dataDirectoryOffset = 112;
    } else {
        info.error = L"unknown optional header magic";
        return info;
    }

    const uint64_t securityDirEntry = optionalOffset + dataDirectoryOffset +
                                      4 * sizeof(IMAGE_DATA_DIRECTORY);

    if (fileHeader.SizeOfOptionalHeader < dataDirectoryOffset + 5 * sizeof(IMAGE_DATA_DIRECTORY)) {
        info.error = L"optional header is too small to contain the security directory";
        return info;
    }
    if (securityDirEntry + sizeof(IMAGE_DATA_DIRECTORY) > info.fileSize) {
        info.error = L"security directory lies outside the file";
        return info;
    }

    IMAGE_DATA_DIRECTORY securityDir{};
    if (!ReadExact(file, securityDirEntry, &securityDir, sizeof(securityDir))) {
        info.error = L"failed to read the security directory";
        return info;
    }

    if ((securityDir.VirtualAddress == 0) != (securityDir.Size == 0)) {
        info.error = L"security directory is inconsistent (offset/size mismatch)";
        return info;
    }
    if (securityDir.VirtualAddress != 0) {
        if (securityDir.VirtualAddress > info.fileSize ||
            securityDir.Size > info.fileSize - securityDir.VirtualAddress) {
            info.error = L"certificate table points outside the file";
            return info;
        }
    }

    info.valid = true;
    info.machine = fileHeader.Machine;
    info.certOffset = securityDir.VirtualAddress;
    info.certSize = securityDir.Size;
    info.certDirEntryOffset = securityDirEntry;
    return info;
}

inline bool HasSignature(const PeInfo& info) {
    return info.valid && info.certOffset != 0 && info.certSize != 0;
}

// ---------------------------------------------------------------------------
// Signature grafting: copy the donor certificate table into the target.
// ---------------------------------------------------------------------------

inline bool CopySignature(const std::wstring& donorPath,
                          const std::wstring& targetPath,
                          std::wstring& error) {
    const PeInfo donor = InspectPe(donorPath);
    if (!donor.valid) {
        error = L"donor: " + donor.error;
        return false;
    }
    if (!HasSignature(donor)) {
        error = L"donor file is not Authenticode-signed";
        return false;
    }

    std::vector<uint8_t> certificate(donor.certSize);
    {
        std::ifstream donorFile(fs::path(donorPath), std::ios::binary);
        if (!donorFile ||
            !ReadExact(donorFile, donor.certOffset, certificate.data(), certificate.size())) {
            error = L"failed to read the donor certificate table";
            return false;
        }
    }

    const PeInfo target = InspectPe(targetPath);
    if (!target.valid) {
        error = L"target: " + target.error;
        return false;
    }

    std::error_code ec;
    const uint64_t originalSize = fs::file_size(fs::path(targetPath), ec);
    if (ec) {
        const std::string message = ec.message();
        error = L"failed to measure target file: " + std::wstring(message.begin(), message.end());
        return false;
    }

    // If the target already ends with its own certificate table, drop it before
    // appending the donor table. Without this, re-signing the same file grows it
    // on every run and leaves the old signature orphaned in the middle.
    uint64_t baseSize = originalSize;
    if (target.certOffset != 0 && target.certSize != 0) {
        const uint64_t certStart = target.certOffset;
        const uint64_t certEnd = certStart + target.certSize;
        if (certEnd == originalSize) {
            std::error_code truncEc;
            fs::resize_file(fs::path(targetPath), certStart, truncEc);
            if (truncEc) {
                const std::string message = truncEc.message();
                error = L"failed to remove the old certificate table: " +
                        std::wstring(message.begin(), message.end());
                return false;
            }
            baseSize = certStart;
        }
    }

    const uint64_t alignedOffset = (baseSize + 7ULL) & ~7ULL;
    const uint64_t newSize = alignedOffset + certificate.size();
    if (newSize > 0xFFFFFFFFULL) {
        error = L"resulting file is too large for a 32-bit certificate directory";
        return false;
    }

    {
        std::ofstream output(fs::path(targetPath), std::ios::binary | std::ios::app);
        if (!output) {
            error = L"failed to open target for append";
            return false;
        }

        if (alignedOffset > baseSize) {
            const uint8_t zero[8] = {};
            output.write(reinterpret_cast<const char*>(zero),
                         static_cast<std::streamsize>(alignedOffset - baseSize));
        }
        output.write(reinterpret_cast<const char*>(certificate.data()),
                     static_cast<std::streamsize>(certificate.size()));
        if (!output) {
            error = L"failed to append the certificate table";
            return false;
        }
    }

    {
        std::fstream patch(fs::path(targetPath), std::ios::binary | std::ios::in | std::ios::out);
        if (!patch) {
            error = L"failed to reopen target to patch the security directory";
            return false;
        }

        const uint32_t newOffset = static_cast<uint32_t>(alignedOffset);
        const uint32_t newLength = static_cast<uint32_t>(certificate.size());

        patch.seekp(static_cast<std::streamoff>(target.certDirEntryOffset), std::ios::beg);
        patch.write(reinterpret_cast<const char*>(&newOffset), sizeof(newOffset));
        patch.write(reinterpret_cast<const char*>(&newLength), sizeof(newLength));

        if (!patch) {
            error = L"failed to update the security directory";
            return false;
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Metadata cloning (icons, version info, manifest) - optional
// ---------------------------------------------------------------------------

struct ResourceEnumContext {
    HMODULE source = nullptr;
    HANDLE update = nullptr;
    bool updateFailed = false;
    DWORD updateError = ERROR_SUCCESS;
};

inline BOOL CALLBACK CopyResourceLanguage(HMODULE module, LPCWSTR type, LPCWSTR name,
                                          WORD language, LONG_PTR parameter) {
    auto* context = reinterpret_cast<ResourceEnumContext*>(parameter);
    HRSRC resource = FindResourceExW(module, type, name, language);
    if (!resource) return TRUE;

    HGLOBAL loaded = LoadResource(module, resource);
    if (!loaded) return TRUE;

    void* data = LockResource(loaded);
    const DWORD size = SizeofResource(module, resource);
    if (data && size) {
        if (!UpdateResourceW(context->update, type, name, language, data, size)) {
            if (!context->updateFailed) {
                context->updateFailed = true;
                context->updateError = GetLastError();
            }
        }
    }
    return TRUE;
}

inline BOOL CALLBACK CopyResourceName(HMODULE module, LPCWSTR type, LPWSTR name,
                                      LONG_PTR parameter) {
    EnumResourceLanguagesW(module, type, name, CopyResourceLanguage, parameter);
    return TRUE;
}

inline bool CloneMetadata(const std::wstring& donorPath,
                          const std::wstring& targetPath,
                          std::wstring& error) {
    HMODULE donor = LoadLibraryExW(donorPath.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
    if (!donor) {
        error = L"failed to load donor resources";
        return false;
    }

    HANDLE update = BeginUpdateResourceW(targetPath.c_str(), FALSE);
    if (!update) {
        error = L"failed to open target for resource update";
        FreeLibrary(donor);
        return false;
    }

    ResourceEnumContext context{donor, update};
    EnumResourceNamesW(donor, RT_VERSION, CopyResourceName,
                       reinterpret_cast<LONG_PTR>(&context));
    EnumResourceNamesW(donor, RT_GROUP_ICON, CopyResourceName,
                       reinterpret_cast<LONG_PTR>(&context));
    EnumResourceNamesW(donor, RT_ICON, CopyResourceName,
                       reinterpret_cast<LONG_PTR>(&context));
    EnumResourceNamesW(donor, RT_MANIFEST, CopyResourceName,
                       reinterpret_cast<LONG_PTR>(&context));

    const BOOL committed = EndUpdateResourceW(update, FALSE);
    const DWORD commitError = GetLastError();
    FreeLibrary(donor);

    if (!committed) {
        wchar_t message[192] = {};
        if (context.updateFailed) {
            swprintf_s(message, L"failed to commit resource changes (update error %lu, commit error %lu)",
                       static_cast<unsigned long>(context.updateError),
                       static_cast<unsigned long>(commitError));
        } else {
            swprintf_s(message, L"failed to commit resource changes (Win32 error %lu)",
                       static_cast<unsigned long>(commitError));
        }
        error = message;
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Signer / verification helpers
// ---------------------------------------------------------------------------

inline std::wstring GetSignerName(const std::wstring& path) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          &encoding, &contentType, &formatType,
                          &store, &message, nullptr)) {
        return L"";
    }

    std::wstring result;
    DWORD signerSize = 0;
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) &&
        signerSize > 0) {
        std::vector<BYTE> buffer(signerSize);
        if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer.data(), &signerSize)) {
            auto* signer = reinterpret_cast<CMSG_SIGNER_INFO*>(buffer.data());

            CERT_INFO certInfo{};
            certInfo.Issuer = signer->Issuer;
            certInfo.SerialNumber = signer->SerialNumber;

            PCCERT_CONTEXT certificate = CertFindCertificateInStore(
                store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

            if (certificate) {
                wchar_t name[512] = {};
                if (CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       0, nullptr, name, 512) > 1) {
                    result = name;
                }
                CertFreeCertificateContext(certificate);
            }
        }
    }

    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return result;
}

inline std::wstring ExplainTrustStatus(LONG status) {
    switch (static_cast<DWORD>(status)) {
    case ERROR_SUCCESS:
        return L"VALID - WinVerifyTrust accepted the signature";
    case TRUST_E_NOSIGNATURE:
        return L"NO SIGNATURE - TRUST_E_NOSIGNATURE (0x800B0100)";
    case TRUST_E_BAD_DIGEST:
        return L"BAD DIGEST - signature is present but the file hash does not match (0x80096010)";
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
        return L"TRUST_E_SUBJECT_FORM_UNKNOWN - subject form not recognized (0x800B0003)";
    case TRUST_E_PROVIDER_UNKNOWN:
        return L"TRUST_E_PROVIDER_UNKNOWN - trust provider not registered (0x800B0001)";
    case TRUST_E_EXPLICIT_DISTRUST:
        return L"EXPLICIT DISTRUST - publisher is explicitly distrusted (0x800B0111)";
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        return L"SUBJECT NOT TRUSTED - certificate is not trusted (0x800B0004)";
    case CERT_E_UNTRUSTEDROOT:
        return L"UNTRUSTED ROOT - certificate chain ends in an untrusted root (0x800B0109)";
    case CERT_E_CHAINING:
        return L"CHAINING FAILURE - certificate chain could not be built (0x800B010A)";
    case CERT_E_EXPIRED:
        return L"EXPIRED - signing certificate has expired (0x800B0101)";
    case CERT_E_REVOKED:
        return L"REVOKED - signing certificate was revoked (0x800B010C)";
    case CERT_E_REVOCATION_FAILURE:
        return L"REVOCATION CHECK FAILED - could not check certificate status (0x800B010E)";
    case CRYPT_E_SECURITY_SETTINGS:
        return L"CRYPT_E_SECURITY_SETTINGS - blocked by security policy (0x80092026)";
    default: {
        wchar_t text[128] = {};
        swprintf_s(text, L"WinVerifyTrust returned 0x%08lX",
                   static_cast<unsigned long>(status));
        return text;
    }
    }
}

struct VerifyResult {
    LONG status = TRUST_E_NOSIGNATURE;
    std::wstring description;
    bool valid() const { return status == ERROR_SUCCESS; }
};

inline VerifyResult VerifyFile(const std::wstring& path) {
    VerifyResult result;

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    result.status = WinVerifyTrust(nullptr, &action, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trustData);

    result.description = ExplainTrustStatus(result.status);
    return result;
}

// ---------------------------------------------------------------------------
// Code Integrity probe (read-only)
// ---------------------------------------------------------------------------

struct CiState {
    bool ok = false;
    ULONG flags = 0;
    std::wstring error;
};

inline CiState ProbeCodeIntegrity() {
    struct CodeIntegrityInformation {
        ULONG length;
        ULONG options;
    };

    using NtQuerySystemInformationFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return {false, 0, L"ntdll.dll is not loaded"};
    }

    auto query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (!query) {
        return {false, 0, L"NtQuerySystemInformation not found"};
    }

    CodeIntegrityInformation info{sizeof(info), 0};
    const LONG status = query(0x67 /* SystemCodeIntegrityInformation */,
                              &info, sizeof(info), nullptr);
    if (status != 0) {
        wchar_t text[96] = {};
        swprintf_s(text, L"NtQuerySystemInformation failed (0x%08lX)",
                   static_cast<unsigned long>(status));
        return {false, 0, text};
    }

    return {true, info.options, L""};
}

} // namespace pesign
