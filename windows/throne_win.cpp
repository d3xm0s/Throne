// Throne for Windows - privilege escalation enumerator
// C++17, WinAPI only, single binary. No dependencies, no writes to disk.

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using std::string;
using std::wstring;
using std::vector;

// ---------------------------------------------------------------------------
// findings

enum Severity { INFO = 0, LOW, MEDIUM, HIGH, CRITICAL };

static const char* SEV_NAMES[] = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"};

struct Finding {
    Severity sev;
    string title;
    string detail;
    string exploit;
};

struct Result {
    string name;
    vector<Finding> findings;
    void add(Severity sev, string title, string detail = "", string exploit = "") {
        findings.push_back({sev, std::move(title), std::move(detail), std::move(exploit)});
    }
};

// ---------------------------------------------------------------------------
// console / color

static bool g_color = true;
static Severity g_min_sev = INFO;

static void enable_vt() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        if (!SetConsoleMode(h, mode | 0x0004))  // ENABLE_VIRTUAL_TERMINAL_PROCESSING
            g_color = false;
    } else {
        g_color = false;
    }
    SetConsoleOutputCP(CP_UTF8);
}

static const char* sev_color(Severity s) {
    switch (s) {
        case INFO: return "\033[36m";
        case LOW: return "\033[34m";
        case MEDIUM: return "\033[33m";
        case HIGH: return "\033[31m";
        case CRITICAL: return "\033[35;1m";
    }
    return "";
}

static void print_finding(const Finding& f, bool last) {
    char tag[16];
    snprintf(tag, sizeof(tag), "[%-8s]", SEV_NAMES[f.sev]);
    const char* branch = last ? "└─" : "├─";
    const char* stem = last ? "   " : "│  ";
    if (g_color)
        printf("  %s %s%s\033[0m %s\n", branch, sev_color(f.sev), tag, f.title.c_str());
    else
        printf("  %s %s %s\n", branch, tag, f.title.c_str());
    if (!f.detail.empty())
        printf("  %s%s%s%s\n", stem, g_color ? "\033[2m" : "", f.detail.c_str(), g_color ? "\033[0m" : "");
    if (!f.exploit.empty())
        printf("  %s%s-> %s%s\n", stem, g_color ? sev_color(f.sev) : "", f.exploit.c_str(), g_color ? "\033[0m" : "");
}

// ---------------------------------------------------------------------------
// string helpers

static string w2u(const wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), n, nullptr, nullptr);
    return out;
}

static wstring u2w(const string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

static string lower(string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)tolower(c); });
    return s;
}

static bool starts_with(const string& s, const string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static vector<string> run_command(const char* cmd) {
    vector<string> lines;
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) return lines;
    char buf[1024];
    string pending;
    while (fgets(buf, sizeof(buf), pipe)) pending += buf;
    _pclose(pipe);
    size_t pos = 0;
    while (pos < pending.size()) {
        size_t nl = pending.find('\n', pos);
        if (nl == string::npos) nl = pending.size();
        string line = pending.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
        pos = nl + 1;
    }
    return lines;
}

// ---------------------------------------------------------------------------
// access checks - real ACL evaluation, never opens anything for writing

static bool access_check(const wstring& path, DWORD desired, SE_OBJECT_TYPE type = SE_FILE_OBJECT) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), type, DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, nullptr, nullptr, &sd) != ERROR_SUCCESS)
        return false;

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_IMPERSONATE, &token)) {
        LocalFree(sd);
        return false;
    }
    HANDLE imp = nullptr;
    bool ok = DuplicateToken(token, SecurityImpersonation, &imp) != 0;
    CloseHandle(token);
    if (!imp) {
        LocalFree(sd);
        return false;
    }

    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    DWORD want = desired;
    MapGenericMask(&want, &mapping);
    PRIVILEGE_SET privs = {};
    DWORD privs_len = sizeof(privs);
    DWORD granted = 0;
    BOOL status = FALSE;
    BOOL ok_access = AccessCheck(sd, imp, want, &mapping, &privs, &privs_len, &granted, &status);

    CloseHandle(imp);
    LocalFree(sd);
    return ok_access && status;
}

static bool can_write_file(const wstring& path) {
    return access_check(path, FILE_GENERIC_WRITE);
}

static bool can_write_dir(const wstring& path) {
    return access_check(path, FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY);
}

// ---------------------------------------------------------------------------
// registry helpers

static bool reg_read_dword(HKEY root, const wchar_t* sub, const wchar_t* name, DWORD& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    DWORD type = 0, size = sizeof(out);
    LONG rc = RegQueryValueExW(key, name, nullptr, &type, (LPBYTE)&out, &size);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS && type == REG_DWORD;
}

static bool reg_read_str(HKEY root, const wchar_t* sub, const wchar_t* name, wstring& out) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    wchar_t buf[1024];
    DWORD type = 0, size = sizeof(buf);
    LONG rc = RegQueryValueExW(key, name, nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(key);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return false;
    out.assign(buf);
    return true;
}

static bool reg_writable(HKEY root, const wchar_t* sub) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_WRITE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    RegCloseKey(key);
    return true;
}

// ---------------------------------------------------------------------------
// check: system info + kernel version

typedef LONG(WINAPI* RtlGetVersionFn)(PRTL_OSVERSIONINFOW);

static void get_os_version(DWORD& major, DWORD& minor, DWORD& build) {
    major = minor = build = 0;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    auto fn = (RtlGetVersionFn)GetProcAddress(ntdll, "RtlGetVersion");
    if (!fn) return;
    RTL_OSVERSIONINFOW info = {};
    info.dwOSVersionInfoSize = sizeof(info);
    if (fn(&info) == 0) {
        major = info.dwMajorVersion;
        minor = info.dwMinorVersion;
        build = info.dwBuildNumber;
    }
}

static string os_name(DWORD major, DWORD build) {
    wstring product;
    if (reg_read_str(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductName", product))
        return w2u(product);
    if (major == 10) return build >= 22000 ? "Windows 11" : "Windows 10";
    return "Windows (build " + std::to_string(build) + ")";
}

static Result check_system() {
    Result r;
    r.name = "system";
    DWORD major, minor, build;
    get_os_version(major, minor, build);
    DWORD ubr = 0;
    reg_read_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", ubr);

    char ver[128];
    snprintf(ver, sizeof(ver), "%s (%lu.%lu.%lu.%lu)", os_name(major, build).c_str(), major, minor, build, ubr);
    r.add(INFO, ver);

    wchar_t host[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD host_len = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(host, &host_len)) {
        char line[256];
        snprintf(line, sizeof(line), "host: %s  arch: %s", w2u(host).c_str(),
                 sizeof(void*) == 8 ? "x64" : "x86");
        r.add(INFO, line);
    }

    // PrintNightmare CVE-2021-34527 - patched UBR per build (heuristic)
    static const std::map<DWORD, DWORD> pn_patched = {
        {10240, 18967}, {14393, 4467}, {17763, 2090}, {18362, 1646},
        {18363, 1646}, {19041, 1083}, {19042, 1083}, {19043, 1083},
    };
    auto it = pn_patched.find(build);
    if (it != pn_patched.end() && ubr < it->second) {
        char msg[160];
        snprintf(msg, sizeof(msg), "build %lu.%lu looks unpatched for PrintNightmare (CVE-2021-34527)", build, ubr);
        r.add(HIGH, msg, "spooler RCE/LPE - patched at UBR " + std::to_string(it->second),
              "if the spooler is running, public exploits give SYSTEM");
    }

    // SeriousSAM / HiveNightmare CVE-2021-36934 - live ACL check on SAM hive
    wchar_t windir[MAX_PATH];
    GetWindowsDirectoryW(windir, MAX_PATH);
    wstring sam = wstring(windir) + L"\\System32\\config\\SAM";
    if (GetFileAttributesW(sam.c_str()) != INVALID_FILE_ATTRIBUTES && access_check(sam, FILE_GENERIC_READ)) {
        r.add(CRITICAL, "SAM hive readable by current user (HiveNightmare CVE-2021-36934)",
              w2u(sam), "copy SAM/SYSTEM from a shadow copy, dump hashes offline");
    }
    return r;
}

// ---------------------------------------------------------------------------
// check: token privileges and integrity

static const struct {
    const wchar_t* name;
    Severity sev;
    const char* hint;
} DANGEROUS_PRIVS[] = {
    {L"SeImpersonatePrivilege", CRITICAL, "potato family: PrintSpoofer / GodPotato / SweetPotato - SYSTEM shell"},
    {L"SeAssignPrimaryTokenPrivilege", HIGH, "potato variants (needs SeImpersonate too on most paths)"},
    {L"SeDebugPrivilege", CRITICAL, "open/inject into any SYSTEM process"},
    {L"SeTcbPrivilege", CRITICAL, "act as part of the OS - craft any token"},
    {L"SeCreateTokenPrivilege", CRITICAL, "create a SYSTEM token directly"},
    {L"SeLoadDriverPrivilege", HIGH, "load a vulnerable driver - BYOVD to kernel"},
    {L"SeBackupPrivilege", HIGH, "read any file - grab SAM/SYSTEM hives"},
    {L"SeRestorePrivilege", HIGH, "write anywhere / take over services"},
    {L"SeTakeOwnershipPrivilege", HIGH, "take ownership of any object, then rewrite it"},
};

static Result check_token() {
    Result r;
    r.name = "token";

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        r.add(INFO, "cannot open process token");
        return r;
    }

    // user
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    vector<BYTE> buf(size);
    if (GetTokenInformation(token, TokenUser, buf.data(), size, &size)) {
        auto tu = (TOKEN_USER*)buf.data();
        wchar_t name[256] = {}, dom[256] = {};
        DWORD nl = 256, dl = 256;
        SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nl, dom, &dl, &use))
            r.add(INFO, "user: " + w2u(dom) + "\\" + w2u(name));
    }

    // integrity level
    size = 0;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
    buf.assign(size, 0);
    if (GetTokenInformation(token, TokenIntegrityLevel, buf.data(), size, &size)) {
        auto til = (TOKEN_MANDATORY_LABEL*)buf.data();
        DWORD rid = *GetSidSubAuthority(til->Label.Sid, *GetSidSubAuthorityCount(til->Label.Sid) - 1);
        const char* level = rid >= 0x4000 ? "high" : rid >= 0x3000 ? "medium" : rid >= 0x2000 ? "low" : "untrusted";
        string line = string("integrity level: ") + level;
        if (rid >= 0x4000)
            r.add(MEDIUM, line, "", "already elevated - look for direct SYSTEM paths (services, tasks)");
        else
            r.add(INFO, line);
    }

    // elevation
    TOKEN_ELEVATION elev = {};
    size = sizeof(elev);
    if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size) && elev.TokenIsElevated)
        r.add(MEDIUM, "token is elevated", "", "admin context - one step from SYSTEM");

    // privileges
    size = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &size);
    buf.assign(size, 0);
    if (GetTokenInformation(token, TokenPrivileges, buf.data(), size, &size)) {
        auto tp = (TOKEN_PRIVILEGES*)buf.data();
        for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
            wchar_t pname[128];
            DWORD plen = 128;
            if (!LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid, pname, &plen)) continue;
            bool enabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
            for (const auto& dp : DANGEROUS_PRIVS) {
                if (wcscmp(pname, dp.name) == 0) {
                    string state = enabled ? "enabled" : "disabled (can be re-enabled)";
                    r.add(dp.sev, w2u(pname) + " " + state, "", dp.hint);
                }
            }
        }
    }
    CloseHandle(token);
    return r;
}

// ---------------------------------------------------------------------------
// check: services - unquoted paths, writable binaries, weak DACLs

static wstring service_binary_path(const wstring& binpath) {
    // strip arguments: quoted path or first token
    wstring p = binpath;
    if (!p.empty() && p[0] == L'"') {
        size_t end = p.find(L'"', 1);
        return end == wstring::npos ? p : p.substr(1, end - 1);
    }
    size_t sp = p.find(L' ');
    return sp == wstring::npos ? p : p.substr(0, sp);
}

static wstring expand_env(const wstring& s) {
    wchar_t buf[2048];
    DWORD n = ExpandEnvironmentStringsW(s.c_str(), buf, 2048);
    return n ? wstring(buf) : s;
}

static Result check_services() {
    Result r;
    r.name = "services";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        r.add(INFO, "cannot open service control manager");
        return r;
    }

    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &needed, &count, &resume, nullptr);
    vector<BYTE> buf(needed);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), needed, &needed, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return r;
    }

    auto services = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    for (DWORD i = 0; i < count; i++) {
        SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (!svc) continue;
        DWORD qneeded = 0;
        QueryServiceConfigW(svc, nullptr, 0, &qneeded);
        vector<BYTE> qbuf(qneeded);
        if (QueryServiceConfigW(svc, (LPQUERY_SERVICE_CONFIGW)qbuf.data(), qneeded, &qneeded)) {
            auto cfg = (LPQUERY_SERVICE_CONFIGW)qbuf.data();
            wstring binpath = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
            wstring name = services[i].lpServiceName;
            CloseServiceHandle(svc);

            wstring expanded = expand_env(binpath);
            string bin_u8 = w2u(expanded);

            // unquoted path with spaces BEFORE the .exe - spaces after are just arguments
            wstring lowpath = expanded;
            std::transform(lowpath.begin(), lowpath.end(), lowpath.begin(), ::towlower);
            size_t exe_pos = lowpath.find(L".exe");
            size_t space_pos = expanded.find(L' ');
            bool unquoted = !expanded.empty() && expanded[0] != L'"' && exe_pos != wstring::npos &&
                            space_pos != wstring::npos && space_pos < exe_pos;
            if (unquoted) {
                vector<wstring> candidates;
                size_t pos = 0;
                while ((pos = expanded.find(L' ', pos)) != wstring::npos && pos < exe_pos) {
                    wstring prefix = expanded.substr(0, pos);
                    if (prefix.size() > 3) {
                        wstring dir = prefix.substr(0, prefix.find_last_of(L'\\'));
                        wstring fake = prefix + L".exe";
                        if (!dir.empty() && can_write_dir(dir))
                            candidates.push_back(fake);
                    }
                    pos++;
                }
                if (!candidates.empty()) {
                    string det = "service " + w2u(name) + " -> " + bin_u8;
                    string ex = "plant " + w2u(candidates[0]) + " - it runs as the service account on restart";
                    r.add(CRITICAL, "unquoted service path with writable dir", det, ex);
                } else {
                    r.add(LOW, "unquoted service path", "service " + w2u(name) + " -> " + bin_u8,
                          "no writable intermediate dirs found");
                }
            }

            // writable binary
            wstring exe = service_binary_path(expanded);
            if (exe.size() > 4 && GetFileAttributesW(exe.c_str()) != INVALID_FILE_ATTRIBUTES &&
                can_write_file(exe)) {
                r.add(CRITICAL, "writable service binary: " + w2u(exe),
                      "service " + w2u(name),
                      "overwrite the binary, restart the service - code runs as the service account");
            }

            // weak service DACL via SDDL
            PSECURITY_DESCRIPTOR sd = nullptr;
            DWORD sdsize = 0;
            SC_HANDLE svc2 = OpenServiceW(scm, services[i].lpServiceName, READ_CONTROL);
            if (svc2) {
                QueryServiceObjectSecurity(svc2, DACL_SECURITY_INFORMATION, nullptr, 0, &sdsize);
                vector<BYTE> sdbuf(sdsize);
                if (QueryServiceObjectSecurity(svc2, DACL_SECURITY_INFORMATION,
                                               (PSECURITY_DESCRIPTOR)sdbuf.data(), sdsize, &sdsize)) {
                    LPWSTR sddl = nullptr;
                    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                            sdbuf.data(), SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, nullptr)) {
                        string s = w2u(sddl);
                        // Everyone / Users / AuthUsers with change-config rights
                        bool weak = s.find(";;;WD)") != string::npos || s.find(";;;BU)") != string::npos ||
                                    s.find(";;;AU)") != string::npos;
                        bool write_rights = s.find("RPWP") != string::npos || s.find("WDWO") != string::npos ||
                                            s.find("CC") != string::npos;
                        if (weak && write_rights) {
                            r.add(CRITICAL, "service DACL allows modification: " + w2u(name),
                                  "sc sdshow " + w2u(name) + " for details",
                                  "sc config " + w2u(name) + " binpath= \"<payload>\" then restart");
                        }
                        LocalFree(sddl);
                    }
                }
                CloseServiceHandle(svc2);
            }
        } else {
            CloseServiceHandle(svc);
        }
    }
    CloseServiceHandle(scm);
    if (r.findings.empty()) r.add(INFO, "no obvious service weaknesses");
    return r;
}

// ---------------------------------------------------------------------------
// check: autoruns - Run keys and startup folders

static string first_exe(const string& cmdline) {
    string s = cmdline;
    if (!s.empty() && s[0] == '"') {
        size_t end = s.find('"', 1);
        return end == string::npos ? s : s.substr(1, end - 1);
    }
    size_t sp = s.find(' ');
    return sp == string::npos ? s : s.substr(0, sp);
}

static void scan_run_key(Result& r, HKEY root, const wchar_t* sub, const char* label) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return;
    DWORD idx = 0;
    wchar_t name[256];
    BYTE data[2048];
    while (true) {
        DWORD nl = 256, dl = sizeof(data), type = 0;
        LONG rc = RegEnumValueW(key, idx++, name, &nl, nullptr, &type, data, &dl);
        if (rc != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        string value = w2u(expand_env((wchar_t*)data));
        string exe = first_exe(value);
        if (exe.size() > 4 && can_write_file(u2w(exe))) {
            r.add(HIGH, string("writable autorun binary (") + label + "): " + exe,
                  "value " + w2u(name),
                  "overwrite it - payload runs on next logon of the affected user");
        }
    }
    RegCloseKey(key);
    if (reg_writable(root, sub)) {
        r.add(HIGH, string("writable Run key: ") + label,
              w2u(sub), "add a value - payload runs as any user who logs on");
    }
}

static Result check_autoruns() {
    Result r;
    r.name = "autoruns";
    scan_run_key(r, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run");
    scan_run_key(r, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM RunOnce");
    scan_run_key(r, HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run x86");

    wchar_t startup[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, startup))) {
        if (can_write_dir(startup)) {
            r.add(HIGH, "all-users startup folder is writable", w2u(startup),
                  "drop an exe/lnk - runs at every logon");
        }
    }
    if (r.findings.empty()) r.add(INFO, "no writable autorun locations");
    return r;
}

// ---------------------------------------------------------------------------
// check: registry misconfig

static Result check_registry() {
    Result r;
    r.name = "registry";

    DWORD dw = 0;
    bool hklm = reg_read_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated", dw) && dw == 1;
    DWORD dw2 = 0;
    bool hkcu = reg_read_dword(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer", L"AlwaysInstallElevated", dw2) && dw2 == 1;
    if (hklm && hkcu) {
        r.add(CRITICAL, "AlwaysInstallElevated = 1 (HKLM + HKCU)",
              "", "msfvenom -f msi -p windows/x64/shell_reverse_tcp ... - msiexec runs it as SYSTEM");
    }

    DWORD lua = 1;
    reg_read_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", lua);
    if (lua == 0) {
        r.add(HIGH, "UAC disabled (EnableLUA = 0)", "", "admin users run everything elevated - no UAC bypass needed");
    }

    // autologon credentials
    wstring auto_admin, user, pass, dom;
    if (reg_read_str(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"AutoAdminLogon", auto_admin) &&
        auto_admin == L"1") {
        reg_read_str(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"DefaultUserName", user);
        bool has_pass = reg_read_str(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"DefaultPassword", pass) && !pass.empty();
        string det = "user: " + w2u(user) + (has_pass ? "  password: " + w2u(pass).substr(0, 2) + "***" : "");
        r.add(has_pass ? CRITICAL : MEDIUM, "AutoAdminLogon enabled", det,
              has_pass ? "plaintext credentials in Winlogon - reuse for lateral movement" : "auto-logon configured");
    }

    // WSUS over HTTP
    DWORD use_wus = 0;
    wstring wuserver;
    if (reg_read_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", L"UseWUServer", use_wus) &&
        use_wus == 1 &&
        reg_read_str(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate", L"WUServer", wuserver) &&
        starts_with(lower(w2u(wuserver)), "http://")) {
        r.add(HIGH, "WSUS updates over plain HTTP", w2u(wuserver),
              "mitm the update channel (WSUSpect / pywsus) - SYSTEM code exec on update");
    }

    if (r.findings.empty()) r.add(INFO, "no registry misconfigurations");
    return r;
}

// ---------------------------------------------------------------------------
// check: scheduled tasks as SYSTEM with writable binaries

static Result check_tasks() {
    Result r;
    r.name = "tasks";

    auto lines = run_command("schtasks /query /xml ONE 2>nul");
    string xml;
    for (const auto& l : lines) { xml += l; xml += "\n"; }
    if (xml.empty()) {
        r.add(INFO, "schtasks unavailable");
        return r;
    }

    int hits = 0;
    // split into <Task> blocks
    size_t pos = 0;
    while (true) {
        size_t start = xml.find("<Task", pos);
        if (start == string::npos) break;
        size_t end = xml.find("</Task>", start);
        if (end == string::npos) break;
        string task = xml.substr(start, end - start);
        pos = end + 7;

        string low = lower(task);
        bool system_task = low.find("s-1-5-18") != string::npos || low.find("<userid>system</userid>") != string::npos;
        if (!system_task) continue;

        size_t cs = task.find("<Command>");
        if (cs == string::npos) continue;
        size_t ce = task.find("</Command>", cs);
        string cmd = task.substr(cs + 9, ce - cs - 9);
        string exe = first_exe(cmd);
        wstring expanded_w = expand_env(u2w(exe));
        if (expanded_w.size() > 4 && GetFileAttributesW(expanded_w.c_str()) != INVALID_FILE_ATTRIBUTES &&
            can_write_file(expanded_w)) {
            hits++;
            r.add(CRITICAL, "SYSTEM scheduled task runs writable binary", w2u(expanded_w),
                  "overwrite it and trigger the task - payload runs as SYSTEM");
        }
    }
    if (hits == 0) r.add(INFO, "no SYSTEM tasks with writable binaries");
    return r;
}

// ---------------------------------------------------------------------------
// check: stored credentials and interesting files

static bool grep_keywords(const wstring& path, vector<string>& matched) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(h, nullptr);
    if (size == INVALID_FILE_SIZE || size > (1 << 20)) {
        CloseHandle(h);
        return false;
    }
    vector<char> buf(size + 1, 0);
    DWORD read = 0;
    ReadFile(h, buf.data(), size, &read, nullptr);
    CloseHandle(h);
    string content(buf.data(), read);
    string lc = lower(content);
    static const char* keys[] = {"password", "passwd", "-enc ", "securestring", "net user", "runas", "credential", "token"};
    for (const char* k : keys) {
        if (lc.find(k) != string::npos) matched.push_back(k);
    }
    return !matched.empty();
}

static Result check_creds() {
    Result r;
    r.name = "creds";

    // cmdkey stored credentials
    auto lines = run_command("cmdkey /list 2>nul");
    for (const auto& l : lines) {
        string lc = lower(l);
        size_t t = lc.find("target:");
        if (t != string::npos) {
            string target = l.substr(t + 7);
            target.erase(0, target.find_first_not_of(" ="));
            r.add(HIGH, "stored credential: " + target, "cmdkey /list",
                  "runas /savecred or reuse via cmdkey-backed tools");
        }
    }

    // unattend / sysprep leftovers
    wchar_t windir[MAX_PATH];
    GetWindowsDirectoryW(windir, MAX_PATH);
    static const wchar_t* candidates[] = {
        L"\\Panther\\Unattend.xml", L"\\Panther\\unattend.xml", L"\\Panther\\Unattended.xml",
        L"\\System32\\sysprep\\unattend.xml", L"\\System32\\sysprep\\sysprep.inf",
        L"\\System32\\sysprep\\Panther\\unattend.xml",
    };
    for (const wchar_t* rel : candidates) {
        wstring path = wstring(windir) + rel;
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        CloseHandle(h);
        r.add(HIGH, "readable answer file: " + w2u(path), "",
              "grep for <Password> - local admin creds from deployment");
    }

    // powershell history
    wchar_t appdata[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) {
        wstring hist = wstring(appdata) + L"\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt";
        vector<string> matched;
        if (grep_keywords(hist, matched)) {
            string keys;
            for (const auto& m : matched) keys += m + " ";
            r.add(MEDIUM, "powershell history contains credential keywords", w2u(hist) + "  [" + keys + "]",
                  "read the history - operators paste secrets constantly");
        }
    }

    if (r.findings.empty()) r.add(INFO, "no stored credentials found");
    return r;
}

// ---------------------------------------------------------------------------
// check: PATH hijack

static Result check_path() {
    Result r;
    r.name = "path";

    wchar_t sys_path[4096];
    DWORD n = GetEnvironmentVariableW(L"PATH", sys_path, 4096);
    if (n == 0) {
        r.add(INFO, "PATH unavailable");
        return r;
    }
    wstring p(sys_path);
    size_t pos = 0;
    while (pos <= p.size()) {
        size_t sc = p.find(L';', pos);
        wstring dir = p.substr(pos, sc == wstring::npos ? wstring::npos : sc - pos);
        pos = sc == wstring::npos ? p.size() + 1 : sc + 1;
        if (dir.empty() || dir == L".") continue;
        if (GetFileAttributesW(dir.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        // skip system-owned dirs that are normally admin-only anyway - can_write decides
        if (can_write_dir(dir)) {
            r.add(HIGH, "writable PATH directory: " + w2u(dir), "",
                  "plant a fake common binary - hijack any process that resolves it");
        }
    }
    if (r.findings.empty()) r.add(INFO, "no writable PATH directories");
    return r;
}

// ---------------------------------------------------------------------------
// check: defenses - Defender, AMSI, LSA protection, AppLocker

static Result check_defenses() {
    Result r;
    r.name = "defenses";

    DWORD dw = 0;
    if (reg_read_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", L"DisableAntiSpyware", dw) && dw == 1)
        r.add(HIGH, "Windows Defender disabled via policy", "DisableAntiSpyware=1",
              "drop and run tools freely - av is off");
    dw = 0;
    if (reg_read_dword(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", L"DisableRealtimeMonitoring", dw) && dw == 1)
        r.add(HIGH, "Defender real-time monitoring off", "", "payloads on disk will not be scanned");

    DWORD ppl = 0;
    bool ppl_set = reg_read_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"RunAsPPL", ppl);
    if (!ppl_set || ppl != 1)
        r.add(HIGH, "LSA protection (RunAsPPL) not enforced", "",
              "with SeDebug/admin, mimikatz can dump lsass - sekurlsa::logonpasswords");

    DWORD cg = 0;
    if (reg_read_dword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LsaCfgFlags", cg) && cg != 0)
        r.add(INFO, "Credential Guard enabled");

    // amsi providers
    HKEY amsi = nullptr;
    int providers = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\AMSI\\Providers", 0, KEY_READ, &amsi) == ERROR_SUCCESS) {
        wchar_t sub[256];
        DWORD idx = 0;
        while (RegEnumKeyW(amsi, idx++, sub, 256) == ERROR_SUCCESS) providers++;
        RegCloseKey(amsi);
        if (providers == 0)
            r.add(MEDIUM, "no AMSI providers registered", "", "in-memory script scanning is effectively off");
        else {
            char msg[64];
            snprintf(msg, sizeof(msg), "%d AMSI provider(s) registered", providers);
            r.add(INFO, msg);
        }
    }

    HKEY srp = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2", 0, KEY_READ, &srp) == ERROR_SUCCESS) {
        RegCloseKey(srp);
        r.add(INFO, "AppLocker policies present", "", "check rule coverage before dropping exe payloads");
    }

    if (r.findings.empty()) r.add(INFO, "no defense weaknesses");
    return r;
}

// ---------------------------------------------------------------------------
// check: wifi passwords and browser credential stores

static Result check_wifi() {
    Result r;
    r.name = "wifi";

    auto lines = run_command("netsh wlan show profiles 2>nul");
    vector<string> profiles;
    for (const auto& l : lines) {
        string lc = lower(l);
        size_t colon = l.rfind(':');
        if (colon == string::npos) continue;
        // en: "All User Profile     : NAME" - ru netsh is OEM-encoded, so match on "profile" only
        if (lc.find("profile") == string::npos) continue;
        string name = l.substr(colon + 1);
        name.erase(0, name.find_first_not_of(" \t"));
        name.erase(name.find_last_not_of(" \t\r") + 1);
        if (!name.empty()) profiles.push_back(name);
    }

    for (const auto& p : profiles) {
        string cmd = "netsh wlan show profile name=\"" + p + "\" key=clear 2>nul";
        auto out = run_command(cmd.c_str());
        for (const auto& l : out) {
            string lc = lower(l);
            if (lc.find("key content") == string::npos && l.find("Содержимое ключа") == string::npos)
                continue;
            size_t colon = l.rfind(':');
            if (colon == string::npos) continue;
            string key = l.substr(colon + 1);
            key.erase(0, key.find_first_not_of(" \t"));
            if (!key.empty())
                r.add(HIGH, "wifi password: " + p, "key: " + key,
                      "reuse for lateral movement - users recycle wifi passwords");
        }
    }
    if (r.findings.empty()) r.add(INFO, profiles.empty() ? "no wifi profiles" : "wifi keys not readable (need admin)");
    return r;
}

static bool file_exists(const wstring& path) {
    return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static Result check_browser() {
    Result r;
    r.name = "browser";

    wchar_t local[MAX_PATH], roaming[MAX_PATH];
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, local))) return r;
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, roaming);

    struct Store { const wchar_t* path; const char* name; };
    const Store chromium_stores[] = {
        {L"\\Google\\Chrome\\User Data\\Default\\Login Data", "chrome"},
        {L"\\Microsoft\\Edge\\User Data\\Default\\Login Data", "edge"},
        {L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", "brave"},
        {L"\\Opera Software\\Opera Stable\\Login Data", "opera"},
    };
    for (const auto& s : chromium_stores) {
        wstring login = wstring(s.name == std::string("opera") ? roaming : local) + s.path;
        if (file_exists(login)) {
            r.add(HIGH, string(s.name) + " credential store present", w2u(login),
                  "same-user context: decrypt via dpapi - mimikatz dpapi::chrome / SharpChrome logins");
        }
    }

    // firefox profiles
    wstring ff = wstring(roaming) + L"\\Mozilla\\Firefox\\Profiles\\*";
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(ff.c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            wstring logins = wstring(roaming) + L"\\Mozilla\\Firefox\\Profiles\\" + fd.cFileName + L"\\logins.json";
            if (file_exists(logins))
                r.add(HIGH, "firefox credential store present", w2u(logins),
                      "logins.json + key4.db -> offline decrypt with firefox_decrypt");
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }

    // dpapi master keys
    wstring mk = wstring(roaming) + L"\\Microsoft\\Protect\\*";
    h = FindFirstFileW(mk.c_str(), &fd);
    int keys = 0;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) {
                wstring dir = wstring(roaming) + L"\\Microsoft\\Protect\\" + fd.cFileName + L"\\*";
                WIN32_FIND_DATAW kd;
                HANDLE kh = FindFirstFileW(dir.c_str(), &kd);
                if (kh != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(kd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) keys++;
                    } while (FindNextFileW(kh, &kd));
                    FindClose(kh);
                }
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (keys > 0) {
        char msg[96];
        snprintf(msg, sizeof(msg), "%d dpapi master key(s) found", keys);
        r.add(MEDIUM, msg, "", "with the user password or domain backup key, these decrypt every saved secret");
    }

    if (r.findings.empty()) r.add(INFO, "no browser credential stores");
    return r;
}

// ---------------------------------------------------------------------------
// check: installed software - password managers and remote tools hold creds

static Result check_software() {
    Result r;
    r.name = "software";

    static const struct { const char* needle; const char* name; const char* hint; } INTERESTING[] = {
        {"keepass", "KeePass", "hunt *.kdbx - keepass2john + hashcat, or keylog the unlock"},
        {"winscp", "WinSCP", "saved sessions decrypt offline - winscp_decrypt / registry Sessions"},
        {"filezilla", "FileZilla", "%APPDATA%\\FileZilla\\sitemanager.xml - plaintext creds"},
        {"putty", "PuTTY", "registry sessions reveal jump hosts; private keys may sit nearby"},
        {"tightvnc", "TightVNC", "registry password is DES with a fixed key - trivially recoverable"},
        {"ultravnc", "UltraVNC", "ultravnc.ini passwd field - fixed DES key"},
        {"realvnc", "RealVNC", "registry obfuscated password - vncpwd recovers it"},
        {"teamviewer", "TeamViewer", "unattended access creds in registry/config"},
        {"anydesk", "AnyDesk", "check unattended access config"},
        {"openvpn", "OpenVPN", "profiles may embed private keys and auth files"},
    };

    const wchar_t* uninstall_roots[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    };
    int found = 0;
    for (const wchar_t* root : uninstall_roots) {
        HKEY base = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, root, 0, KEY_READ, &base) != ERROR_SUCCESS) continue;
        wchar_t sub[256];
        DWORD idx = 0;
        while (RegEnumKeyW(base, idx++, sub, 256) == ERROR_SUCCESS) {
            wstring full = wstring(root) + L"\\" + sub;
            wstring name;
            if (!reg_read_str(HKEY_LOCAL_MACHINE, full.c_str(), L"DisplayName", name)) continue;
            string n = lower(w2u(name));
            for (const auto& s : INTERESTING) {
                if (n.find(s.needle) != string::npos) {
                    found++;
                    r.add(MEDIUM, string("installed: ") + s.name, w2u(name), s.hint);
                    break;
                }
            }
        }
        RegCloseKey(base);
    }
    if (!found) r.add(INFO, "no credential-bearing software detected");
    return r;
}

// ---------------------------------------------------------------------------
// check: loot - filezilla, winscp, putty, rdp, kdbx

static void enum_reg_subkeys(Result& r, HKEY root, const wchar_t* sub, const char* label,
                             Severity sev, const char* hint) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &key) != ERROR_SUCCESS) return;
    wchar_t name[256];
    DWORD idx = 0;
    int count = 0;
    string sample;
    while (RegEnumKeyW(key, idx++, name, 256) == ERROR_SUCCESS) {
        count++;
        if (sample.size() < 120) sample += (sample.empty() ? "" : ", ") + w2u(name);
    }
    RegCloseKey(key);
    if (count > 0) {
        char msg[160];
        snprintf(msg, sizeof(msg), "%d saved %s session(s)", count, label);
        r.add(sev, msg, sample, hint);
    }
}

static void find_files_shallow(Result& r, const wstring& dir, const wchar_t* ext,
                               const char* label, Severity sev, const char* hint, int depth) {
    if (depth <= 0) return;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            find_files_shallow(r, full, L"", label, sev, hint, depth - 1);
            continue;
        }
        wstring name = fd.cFileName;
        string ln = lower(w2u(name));
        bool match = wcslen(ext) == 0
            ? (ln.find("passw") != string::npos || ln.find("cred") != string::npos)
            : ln.size() > 5 && ln.compare(ln.size() - 5, 5, lower(w2u(ext))) == 0;
        if (match) r.add(sev, string(label) + ": " + w2u(full), "", hint);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static Result check_loot() {
    Result r;
    r.name = "loot";

    wchar_t roaming[MAX_PATH], profile[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, roaming);
    SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, profile);

    wstring fz = wstring(roaming) + L"\\FileZilla\\sitemanager.xml";
    if (file_exists(fz))
        r.add(CRITICAL, "filezilla sitemanager.xml - plaintext credentials", w2u(fz),
              "grep for <Pass> - plain ftp/ssh creds, no decryption needed");

    wstring fz_rc = wstring(roaming) + L"\\FileZilla\\recentservers.xml";
    if (file_exists(fz_rc))
        r.add(HIGH, "filezilla recentservers.xml found", w2u(fz_rc), "may hold plaintext credentials");

    enum_reg_subkeys(r, HKEY_CURRENT_USER, L"Software\\Martin Prikryl\\WinSCP 2\\Sessions",
                     "winscp", HIGH, "winscp session passwords decrypt offline (winscp_decrypt)");
    enum_reg_subkeys(r, HKEY_CURRENT_USER, L"Software\\SimonTatham\\PuTTY\\Sessions",
                     "putty", MEDIUM, "session names reveal jump hosts - check for keys in %USERPROFILE%");

    find_files_shallow(r, wstring(profile) + L"\\Documents", L".kdbx", "keepass database", HIGH,
                       "keepass2john + hashcat, or keylog the unlock", 2);
    find_files_shallow(r, wstring(profile) + L"\\Desktop", L".kdbx", "keepass database", HIGH,
                       "keepass2john + hashcat, or keylog the unlock", 2);
    find_files_shallow(r, wstring(profile) + L"\\Downloads", L".kdbx", "keepass database", HIGH,
                       "keepass2john + hashcat, or keylog the unlock", 1);
    find_files_shallow(r, wstring(profile) + L"\\Documents", L".rdp", "rdp file", MEDIUM,
                       "may embed credentials or reveal rdp targets", 2);

    if (r.findings.empty()) r.add(INFO, "no loot files found");
    return r;
}

// ---------------------------------------------------------------------------
// engine

struct CheckDef {
    const char* name;
    Result (*fn)();
};

static const CheckDef CHECKS[] = {
    {"system", check_system}, {"token", check_token}, {"services", check_services},
    {"autoruns", check_autoruns}, {"registry", check_registry}, {"tasks", check_tasks},
    {"creds", check_creds}, {"path", check_path}, {"defenses", check_defenses},
    {"wifi", check_wifi}, {"browser", check_browser}, {"software", check_software},
    {"loot", check_loot},
};

static const char* BANNER = R"(
████████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗███████╗
╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝
   ██║   ███████║██████╔╝██║   ██║██╔██╗ ██║█████╗
   ██║   ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╔╝██║ ╚████║███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝)";

static const char* VERSION = "1.2.0";

static void usage() {
    printf("throne-win %s - windows privilege escalation enumerator\n\n", VERSION);
    printf("usage: throne-win [options]\n\n");
    printf("  --checks a,b,c        run only these checks\n");
    printf("  --min-severity SEV    info|low|medium|high|critical (default: info)\n");
    printf("  --no-color            plain output\n");
    printf("  --fail-on SEV         exit 1 if any finding reaches SEV\n");
    printf("  --list-checks         print available checks\n");
    printf("  --help                this help\n\n");
    printf("checks: ");
    for (const auto& c : CHECKS) printf("%s ", c.name);
    printf("\n");
}

static Severity parse_sev(const string& s) {
    string lc = lower(s);
    for (int i = 0; i <= (int)CRITICAL; i++) {
        string name = lower(SEV_NAMES[i]);
        if (lc == name) return (Severity)i;
    }
    return (Severity)-1;
}

int main(int argc, char** argv) {
    vector<string> selected;
    string fail_on;
    for (int i = 1; i < argc; i++) {
        string arg = argv[i];
        auto next = [&](string& out) -> bool {
            if (i + 1 < argc) { out = argv[++i]; return true; }
            return false;
        };
        if (arg == "--checks") {
            string v;
            if (!next(v)) { usage(); return 2; }
            size_t pos = 0;
            while (pos <= v.size()) {
                size_t c = v.find(',', pos);
                selected.push_back(v.substr(pos, c == string::npos ? string::npos : c - pos));
                pos = c == string::npos ? v.size() + 1 : c + 1;
            }
        } else if (arg == "--min-severity") {
            string v;
            if (!next(v) || (int)(g_min_sev = parse_sev(v)) < 0) { usage(); return 2; }
        } else if (arg == "--fail-on") {
            if (!next(fail_on)) { usage(); return 2; }
        } else if (arg == "--no-color") {
            g_color = false;
        } else if (arg == "--list-checks") {
            for (const auto& c : CHECKS) printf("%s\n", c.name);
            return 0;
        } else if (arg == "--help") {
            usage();
            return 0;
        } else if (arg == "--version") {
            printf("throne-win %s\n", VERSION);
            return 0;
        } else {
            usage();
            return 2;
        }
    }

    enable_vt();

    if (g_color) printf("\033[35;1m%s\033[0m\n", BANNER);
    else printf("%s\n", BANNER);
    printf("%s  windows privilege escalation enumerator v%s%s\n\n",
           g_color ? "\033[2m" : "", VERSION, g_color ? "\033[0m" : "");

    Severity fail_sev = (Severity)-1;
    if (!fail_on.empty()) {
        fail_sev = parse_sev(fail_on);
        if ((int)fail_sev < 0) { usage(); return 2; }
    }

    DWORD started = GetTickCount();
    int counts[5] = {};
    for (const auto& def : CHECKS) {
        if (!selected.empty() &&
            std::find(selected.begin(), selected.end(), def.name) == selected.end())
            continue;
        Result r = def.fn();
        vector<const Finding*> visible;
        for (const auto& f : r.findings) {
            counts[f.sev]++;
            if (f.sev >= g_min_sev) visible.push_back(&f);
        }
        if (visible.empty()) continue;
        if (g_color)
            printf("\033[35;1m==[\033[0m \033[1m%s\033[0m \033[35;1m]%s\033[0m\n", r.name.c_str(),
                   string(std::max<size_t>(2, 60 - r.name.size()), '=').c_str());
        else
            printf("==[ %s ]%s\n", r.name.c_str(), string(std::max<size_t>(2, 60 - r.name.size()), '=').c_str());
        for (size_t i = 0; i < visible.size(); i++)
            print_finding(*visible[i], i == visible.size() - 1);
        printf("\n");
    }

    float elapsed = (GetTickCount() - started) / 1000.0f;
    int total = counts[0] + counts[1] + counts[2] + counts[3] + counts[4];
    printf("%ssummary%s (%d findings in %.1fs)\n", g_color ? "\033[1m" : "", g_color ? "\033[0m" : "", total, elapsed);
    printf("  ");
    bool any = false;
    for (int s = CRITICAL; s >= 0; s--) {
        if (!counts[s]) continue;
        any = true;
        printf("%s%s %d%s  ", g_color ? sev_color((Severity)s) : "", lower(SEV_NAMES[s]).c_str(), counts[s], g_color ? "\033[0m" : "");
    }
    printf("%s\n\n", any ? "" : "clean");

    if ((int)fail_sev >= 0)
        for (int s = (int)fail_sev; s <= (int)CRITICAL; s++)
            if (counts[s]) return 1;
    return 0;
}
