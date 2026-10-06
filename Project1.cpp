// LanFileTransfer.cpp : Win32 GUI 局域网文件传输工具（全设备版 / 修复版）
// 支持 Windows(SMB推送) + 安卓/iOS/任何设备(HTTP浏览器下载/上传)
// 扫描: ping全网段 + ARP兜底 + OUI厂商识别(真实IEEE数据) + SMB OS探测
// 手机识别: 浏览器打开页面后自动上报 UserAgent，解析品牌与型号（vivo/OPPO/华为/小米/荣耀/三星/Apple）

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <winnetwk.h>
#include <lm.h>
#include <lmapibuf.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <filesystem>
#include <atomic>
#include <map>
#include <set>
#include <queue>
#include <functional>
#include <unordered_map>
#include <condition_variable>
#include <algorithm>
#include <cstdio>
#include <cctype>
#include <cwctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace fs = std::filesystem;

// ============== 控件 ID ==============
#define IDC_BTN_SCAN          1001
#define IDC_CHECK_AUTOSEND    1002
#define IDC_LIST_DEVICES      1003
#define IDC_EDIT_FILEPATH     1004
#define IDC_BTN_SELFILE       1005
#define IDC_BTN_SELDIR        1006
#define IDC_EDIT_SHARE        1007
#define IDC_EDIT_USER         1008
#define IDC_EDIT_PASS         1009
#define IDC_BTN_SENDONE       1010
#define IDC_BTN_SENDALL       1011
#define IDC_EDIT_LOG          1012
#define IDC_STATIC_STATUS     1013
#define IDC_STATIC_SCANINFO   1014
#define IDC_EDIT_HTTPPORT     1015
#define IDC_BTN_HTTPSTART     1016
#define IDC_BTN_HTTPSTOP      1017
#define IDC_STATIC_HTTPURL    1018
#define IDC_BTN_OPENURL       1019

// ============== 自定义消息 ==============
#define WM_LOG_MSG            (WM_USER + 100)
#define WM_DEVICE_FOUND       (WM_USER + 101)
#define WM_DEVICE_INFO_READY  (WM_USER + 102)
#define WM_SCAN_PROGRESS      (WM_USER + 103)
#define WM_SCAN_DONE          (WM_USER + 104)
#define WM_STATUS_UPDATE      (WM_USER + 105)
#define WM_HTTP_UPDATE        (WM_USER + 106)
#define WM_UA_REPORT          (WM_USER + 107)

// ============== 设备信息 ==============
struct DeviceInfo {
    std::wstring ip;
    std::wstring hostname;
    std::wstring osName;
    std::wstring deviceType;   // Apple / Android / Windows / 移动设备 / 其他
    std::wstring vendor;       // 厂商名
    std::wstring mac;
    std::wstring status;
    bool hasSMB;
};

// ============== OUI 厂商识别表（真实 IEEE 数据，均匀采样；运行时还会尝试加载同目录 oui.txt 全量） ==============
struct OUIEntry { const char* oui; const wchar_t* vendor; const wchar_t* type; };
const OUIEntry kOUIList[] = {
#include "oui_table.inc"
};

// ============== 全局变量 ==============
HINSTANCE g_hInst = nullptr;
HWND g_hWnd = nullptr;
HWND g_hBtnScan = nullptr;
HWND g_hCheckAutoSend = nullptr;
HWND g_hListDevices = nullptr;
HWND g_hEditFilePath = nullptr;
HWND g_hBtnSelFile = nullptr;
HWND g_hBtnSelDir = nullptr;
HWND g_hEditShare = nullptr;
HWND g_hEditUser = nullptr;
HWND g_hEditPass = nullptr;
HWND g_hBtnSendOne = nullptr;
HWND g_hBtnSendAll = nullptr;
HWND g_hEditLog = nullptr;
HWND g_hStaticStatus = nullptr;
HWND g_hStaticScanInfo = nullptr;
HWND g_hEditHttpPort = nullptr;
HWND g_hBtnHttpStart = nullptr;
HWND g_hBtnHttpStop = nullptr;
HWND g_hStaticHttpUrl = nullptr;
HWND g_hBtnOpenUrl = nullptr;

std::mutex g_logMutex;
std::atomic<bool> g_scanning{ false };
std::atomic<bool> g_sending{ false };
std::atomic<bool> g_httpRunning{ false };
std::atomic<uint64_t> g_scanGen{ 0 };

SOCKET g_httpSock = INVALID_SOCKET;
std::thread g_httpThread;

std::wstring g_selectedPath;
std::wstring g_httpSharePath;   // HTTP 共享路径
std::wstring g_httpRecvDir;     // HTTP 上传接收目录
std::vector<std::wstring> g_foundDevices;
std::mutex g_devicesMutex;
std::map<std::wstring, int> g_ipToRow;
std::mutex g_rowMutex;
std::map<std::wstring, DeviceInfo> g_deviceMap;
std::mutex g_mapMtx;

// HTTP 活跃连接（用于停止时立即唤醒）
std::set<SOCKET> g_activeClients;
std::mutex g_activeMtx;

// ============== 工具函数 ==============
std::wstring GetEditText(HWND hEdit) {
    int len = GetWindowTextLengthW(hEdit);
    if (len == 0) return L"";
    std::wstring buf(len + 1, L'\0');
    GetWindowTextW(hEdit, buf.data(), len + 1);
    buf.resize(len);
    return buf;
}
void SetEditText(HWND hEdit, const std::wstring& text) { SetWindowTextW(hEdit, text.c_str()); }
void Log(const std::wstring& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    int len = GetWindowTextLengthW(g_hEditLog);
    SendMessageW(g_hEditLog, EM_SETSEL, len, len);
    std::wstring line = msg + L"\r\n";
    SendMessageW(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    SendMessageW(g_hEditLog, EM_SCROLLCARET, 0, 0);
}
void PostLog(const std::wstring& msg) {
    std::wstring* p = new std::wstring(msg);
    PostMessageW(g_hWnd, WM_LOG_MSG, 0, (LPARAM)p);
}
void SetStatus(const std::wstring& msg) { SetWindowTextW(g_hStaticStatus, msg.c_str()); }
std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), str.data(), size, nullptr, nullptr);
    return str;
}
std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), wstr.data(), size);
    return wstr;
}
static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}
static std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ============== OS 版本解析 ==============
std::wstring GetOSName(DWORD major, DWORD minor) {
    if (major == 10 && minor == 0) return L"Windows 10/11";
    if (major == 6 && minor == 3) return L"Win8.1/2012R2";
    if (major == 6 && minor == 2) return L"Win8/2012";
    if (major == 6 && minor == 1) return L"Win7/2008R2";
    if (major == 6 && minor == 0) return L"Vista/2008";
    if (major == 5 && minor == 2) return L"XPx64/2003";
    if (major == 5 && minor == 1) return L"Windows XP";
    return L"Win " + std::to_wstring(major) + L"." + std::to_wstring(minor);
}

// ============== 本机网卡 / IP 枚举（解决多网卡、虚拟网卡导致的错误地址） ==============
struct LocalAddr {
    std::string ip;
    std::wstring desc;
    bool hasGateway;
    bool isVirtual;
    bool special;      // fake-ip / 保留 / 测试网段
    DWORD ifType;
};

// 判断是否为 fake-ip / 基准测试 / 链路本地等“不可作为局域网”的特殊网段
static bool IsSpecialSegment(const std::string& ip) {
    unsigned a = 0, b = 0;
    if (sscanf_s(ip.c_str(), "%u.%u", &a, &b) < 1) return true;
    if (a == 0 || a == 127) return true;
    if (a == 169 && b == 254) return true;          // link-local
    if (a == 198 && (b == 18 || b == 19)) return true; // RFC2544 基准段，Clash 等 fake-ip 常用
    if (a >= 224) return true;                       // 组播/保留
    return false;
}
// CGNAT 100.64/10 降权（个别环境也用作内网，不硬排除）
static bool IsCGNAT(const std::string& ip) {
    unsigned a = 0, b = 0;
    if (sscanf_s(ip.c_str(), "%u.%u", &a, &b) < 2) return false;
    return a == 100 && b >= 64 && b <= 127;
}

static bool IsVirtualDesc(const std::wstring& d) {
    std::wstring l = d;
    std::transform(l.begin(), l.end(), l.begin(), ::towlower);
    static const wchar_t* kws[] = {
        L"vmware", L"virtualbox", L"virtual", L"hyper-v", L"hyperv", L"vethernet",
        L"wsl", L"pseudo", L"loopback", L"docker", L"tap", L"bluestacks", L"nox", L"ldplayer",
        L"wintun", L"wireguard", L"openvpn", L"clash", L"mihomo", L"sing-box", L"surge",
        L"tunnel", L"tun", L"zerotier", L"tailscale", L"hamachi", L"radmin", L"netch", L"v2ray"
    };
    for (auto k : kws) if (l.find(k) != std::wstring::npos) return true;
    return false;
}

std::vector<LocalAddr> EnumLocalIPs() {
    std::vector<LocalAddr> out;
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG bufLen = 20000;
    std::vector<unsigned char> buf(bufLen);
    DWORD ret = GetAdaptersAddresses(AF_INET, flags, nullptr,
        (PIP_ADAPTER_ADDRESSES)buf.data(), &bufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr,
            (PIP_ADAPTER_ADDRESSES)buf.data(), &bufLen);
    }
    if (ret != NO_ERROR) return out;

    for (PIP_ADAPTER_ADDRESSES p = (PIP_ADAPTER_ADDRESSES)buf.data(); p != nullptr; p = p->Next) {
        if (p->OperStatus != IfOperStatusUp) continue;
        if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        bool hasGw = false;
        for (PIP_ADAPTER_GATEWAY_ADDRESS g = p->FirstGatewayAddress; g != nullptr; g = g->Next) { hasGw = true; break; }

        std::wstring desc = p->FriendlyName ? p->FriendlyName : L"";
        if (p->Description) { desc += L" / "; desc += p->Description; }
        bool virt = IsVirtualDesc(desc);

        for (PIP_ADAPTER_UNICAST_ADDRESS u = p->FirstUnicastAddress; u != nullptr; u = u->Next) {
            if (u->Address.lpSockaddr->sa_family != AF_INET) continue;
            sockaddr_in* sa = (sockaddr_in*)u->Address.lpSockaddr;
            char tmp[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &sa->sin_addr, tmp, sizeof(tmp));
            std::string sip = tmp;
            if (sip.rfind("169.254", 0) == 0) continue;
            bool special = IsSpecialSegment(sip);
            out.push_back({ sip, desc, hasGw, virt, special, p->IfType });
        }
    }
    return out;
}

// UDP connect 探测默认出口 IP（不实际发包），作为兜底
std::string GetOutboundIP() {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return "";
    sockaddr_in a = { 0 };
    a.sin_family = AF_INET; a.sin_port = htons(53);
    inet_pton(AF_INET, "114.114.114.114", &a.sin_addr);
    std::string ip;
    if (connect(s, (sockaddr*)&a, sizeof(a)) == 0) {
        sockaddr_in local = { 0 }; int len = sizeof(local);
        if (getsockname(s, (sockaddr*)&local, &len) == 0) {
            char tmp[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &local.sin_addr, tmp, sizeof(tmp));
            ip = tmp;
        }
    }
    closesocket(s);
    return ip;
}

// 选择最佳（最可能被手机访问到的）本机 IP
std::string GetBestLocalIP(std::vector<LocalAddr>& addrs, std::wstring* detail = nullptr) {
    auto physical = [](const LocalAddr& a) { return a.ifType == IF_TYPE_ETHERNET_CSMACD ||
        a.ifType == IF_TYPE_IEEE80211; };
    auto good = [&](const LocalAddr& a, bool allowVirtual, bool allowCGNAT) {
        if (a.special) return false;
        if (!allowVirtual && a.isVirtual) return false;
        if (!allowCGNAT && IsCGNAT(a.ip)) return false;
        return true;
    };
    auto pick = [&](bool needGw, bool physOnly, bool allowVirt, bool allowCGNAT) -> const LocalAddr* {
        for (const auto& a : addrs) {
            if (needGw && !a.hasGateway) continue;
            if (physOnly && !physical(a)) continue;
            if (!good(a, allowVirt, allowCGNAT)) continue;
            return &a;
        }
        return nullptr;
    };

    const LocalAddr* a = nullptr;
    a = a ? a : pick(true,  true,  false, false); // 物理 + 有网关
    a = a ? a : pick(true,  true,  true,  false); // 物理 + 有网关(放宽虚拟描述)
    a = a ? a : pick(true,  false, false, false); // 任意真实网卡 + 有网关
    a = a ? a : pick(false, true,  true,  false); // 物理，无网关（直连）
    a = a ? a : pick(true,  false, true,  false); // 任意 + 有网关
    a = a ? a : pick(true,  true,  true,  true);  // CGNAT 降权候选
    a = a ? a : pick(false, false, true,  true);  // 任意非特殊
    if (a) { if (detail) *detail = a->desc; return a->ip; }

    // UDP 兜底：仅在结果不是特殊/fake-ip 网段时采用
    std::string o = GetOutboundIP();
    if (!o.empty() && !IsSpecialSegment(o) && !IsCGNAT(o)) return o;
    return ""; // 找不到安全网卡
}

// 获取默认网关 IPv4（物理网卡优先），用于代理 ARP 过滤
std::string GetDefaultGatewayIP() {
    ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS;
    ULONG bufLen = 20000;
    std::vector<unsigned char> buf(bufLen);
    DWORD ret = GetAdaptersAddresses(AF_INET, flags, nullptr,
        (PIP_ADAPTER_ADDRESSES)buf.data(), &bufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        ret = GetAdaptersAddresses(AF_INET, flags, nullptr,
            (PIP_ADAPTER_ADDRESSES)buf.data(), &bufLen);
    }
    if (ret != NO_ERROR) return "";

    for (int pass = 0; pass < 2; pass++) {
        for (PIP_ADAPTER_ADDRESSES p = (PIP_ADAPTER_ADDRESSES)buf.data(); p; p = p->Next) {
            if (p->OperStatus != IfOperStatusUp) continue;
            if (p->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            std::wstring desc = p->FriendlyName ? p->FriendlyName : L"";
            if (p->Description) desc += p->Description;
            bool virt = IsVirtualDesc(desc);
            if (pass == 0 && virt) continue;
            PIP_ADAPTER_GATEWAY_ADDRESS g = p->FirstGatewayAddress;
            if (!g) continue;
            if (g->Address.lpSockaddr->sa_family != AF_INET) continue;
            sockaddr_in* sa = (sockaddr_in*)g->Address.lpSockaddr;
            char tmp[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &sa->sin_addr, tmp, sizeof(tmp));
            return tmp;
        }
    }
    return "";
}

// ============== Windows 防火墙规则 ==============
bool FirewallRuleExists(int port) {
    std::string cmd = "netsh advfirewall firewall show rule name=\"LanFileTransfer Port " +
        std::to_string(port) + "\"";
    std::string out;
    FILE* pp = _popen(cmd.c_str(), "r");
    if (!pp) return false;
    char buf[1024];
    while (fgets(buf, sizeof(buf), pp)) out += buf;
    _pclose(pp);
    std::string lo = ToLower(out);
    return lo.find("localport") != std::string::npos;
}

bool RunElevatedNetsh(int port) {
    std::wstring params =
        L"advfirewall firewall add rule name=\"LanFileTransfer Port " +
        std::to_wstring(port) +
        L"\" dir=in action=allow protocol=TCP localport=" + std::to_wstring(port);

    SHELLEXECUTEINFOW sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = L"netsh.exe";
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei)) return false; // 用户拒绝 UAC 或失败
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 15000);
        DWORD code = 1;
        GetExitCodeProcess(sei.hProcess, &code);
        CloseHandle(sei.hProcess);
        return code == 0;
    }
    return true;
}

void EnsureFirewallRule(int port) {
    if (FirewallRuleExists(port)) {
        PostLog(L"[防火墙] 端口 " + std::to_wstring(port) + L" 的入站规则已存在");
        return;
    }
    PostLog(L"[防火墙] 未发现放行规则，尝试添加（将弹出一次 UAC 授权，请点“是”）...");
    bool ok = RunElevatedNetsh(port);
    if (ok)
        PostLog(L"[防火墙] 已放行 TCP " + std::to_wstring(port) + L" 入站");
    else
        PostLog(L"[防火墙] 未能自动添加规则。若手机打不开页面：请在 Windows 防火墙弹窗中允许本程序，"
            L"或确认当前 WiFi 的网络位置不是“公用网络”（专用网络更易互通），也可手动放行该端口。");
}

// ============== MAC 地址获取 (SendARP) ==============
std::wstring GetMACAddress(const std::string& ip) {
    IPAddr ipAddr = inet_addr(ip.c_str());
    if (ipAddr == INADDR_NONE) return L"";
    ULONG macAddr[2] = { 0, 0 };
    ULONG macLen = 6;
    DWORD ret = SendARP(ipAddr, 0, macAddr, &macLen);
    if (ret != NO_ERROR || macLen != 6) return L"";
    BYTE* mac = (BYTE*)macAddr;
    wchar_t buf[32];
    swprintf_s(buf, L"%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

// ============== OUI 厂商识别 ==============
std::unordered_map<std::string, std::pair<std::wstring, std::wstring>> g_ouiMap;

static std::pair<std::wstring, std::wstring> MapCompanyName(const std::string& companyLo) {
    struct M { const char* k; const wchar_t* v; const wchar_t* t; };
    static const M tab[] = {
        {"honor",        L"荣耀",   L"Android"},
        {"huawei",       L"华为",   L"Android"},
        {"xiaomi",       L"小米",   L"Android"},
        {"oppo",         L"OPPO",   L"Android"},
        {"vivo",         L"vivo",   L"Android"},
        {"apple",        L"Apple",  L"Apple"},
        {"samsung",      L"三星",   L"Android"},
        {"motorola",     L"摩托罗拉", L"Android"},
        {"lenovo mobile",L"联想",   L"Android"},
        {"lenovo",       L"联想",   L"Windows"},
        {"dell",         L"戴尔",   L"Windows"},
        {"hewlett",      L"惠普",   L"Windows"},
        {"hp inc",       L"惠普",   L"Windows"},
        {"asus",         L"华硕",   L"Windows"},
        {"microsoft",    L"微软",   L"Windows"},
        {"intel",        L"Intel网卡", L"Windows"},
        {"realtek",      L"瑞昱网卡", L"Windows"},
        {"qualcomm",     L"高通",   L"Android"},
        {"mediatek",     L"联发科", L"Android"},
        {"acer",         L"宏碁",   L"Windows"},
    };
    for (const auto& m : tab)
        if (companyLo.find(m.k) != std::string::npos) return { m.v, m.t };
    return { L"", L"" };
}

void BuildOUIMap() {
    for (const auto& e : kOUIList)
        g_ouiMap[e.oui] = { e.vendor, e.type };

    // 可选：加载 exe 同目录的完整 oui.txt
    wchar_t modPath[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, modPath, MAX_PATH);
    fs::path p = fs::path(modPath).parent_path() / L"oui.txt";
    std::error_code ec;
    if (!fs::exists(p, ec)) return;

    std::ifstream f(p);
    if (!f.is_open()) return;
    std::string line;
    int added = 0;
    while (std::getline(f, line)) {
        size_t hx = line.find("(hex)");
        if (hx == std::string::npos) continue;
        std::string prefix = Trim(line.substr(0, hx)); // XX-XX-XX
        if (prefix.size() < 8) continue;
        std::string key;
        key += prefix[0]; key += prefix[1]; key += ':';
        key += prefix[3]; key += prefix[4]; key += ':';
        key += prefix[6]; key += prefix[7];
        std::string company = ToLower(Trim(line.substr(hx + 5)));
        auto vm = MapCompanyName(company);
        if (!vm.first.empty()) {
            if (g_ouiMap.find(key) == g_ouiMap.end()) { g_ouiMap[key] = vm; added++; }
        }
    }
    if (added > 0) PostLog(L"[OUI] 已从 oui.txt 补充 " + std::to_wstring(added) + L" 条厂商前缀");
}

// 判断是否为本地管理（随机/隐私）MAC：第一字节的 bit1 (0x02)
static bool IsRandomMac(const std::wstring& mac) {
    if (mac.size() < 2) return false;
    auto hv = [](wchar_t c) -> int {
        if (c >= L'0' && c <= L'9') return c - L'0';
        if (c >= L'A' && c <= L'F') return c - L'A' + 10;
        if (c >= L'a' && c <= L'f') return c - L'a' + 10;
        return -1;
    };
    int hi = hv(mac[0]);
    return hi >= 0 && (hi & 0x02);
}

bool LookupOUI(const std::wstring& mac, std::wstring& vendor, std::wstring& type) {
    if (mac.size() < 8) return false;
    std::string key = WStringToString(mac.substr(0, 8));
    auto it = g_ouiMap.find(key);
    if (it != g_ouiMap.end()) { vendor = it->second.first; type = it->second.second; return true; }
    return false;
}

// ============== Ping 检测 ==============
bool PingHost(const std::string& ip, int timeoutMs = 400) {
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return false;
    IPAddr ipAddr = inet_addr(ip.c_str());
    char replyBuf[256];
    DWORD replySize = sizeof(replyBuf);
    DWORD ret = IcmpSendEcho(hIcmp, ipAddr, nullptr, 0, nullptr, replyBuf, replySize, timeoutMs);
    IcmpCloseHandle(hIcmp);
    if (ret == 0) return false;
    // 校验：应答状态成功且来源确实是目标 IP，过滤路由器代答/不可达
    ICMP_ECHO_REPLY* er = (ICMP_ECHO_REPLY*)replyBuf;
    return er->Status == IP_SUCCESS && er->Address == ipAddr;
}

// ============== 检测 445 端口（修复：用 SO_ERROR 判定，避免把拒绝误判为开放） ==============
bool CheckSMBPort(const std::string& ip, int timeoutMs = 400) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(445);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    int cr = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (cr == 0) { closesocket(sock); return true; }
    if (WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(sock); return false; }

    fd_set writeSet, errSet;
    FD_ZERO(&writeSet); FD_ZERO(&errSet);
    FD_SET(sock, &writeSet); FD_SET(sock, &errSet);
    struct timeval tv = { 0, timeoutMs * 1000 };
    int result = select(0, nullptr, &writeSet, &errSet, &tv);
    bool open = false;
    if (result > 0) {
        int soerr = 0; int len = sizeof(soerr);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&soerr, &len) == 0 && soerr == 0)
            open = true;
    }
    closesocket(sock);
    return open;
}

// ============== 获取设备完整信息 ==============
DeviceInfo GetDeviceInfo(const std::string& ip) {
    DeviceInfo info;
    info.ip = StringToWString(ip);
    info.status = L"在线";
    info.hasSMB = false;

    // 1. MAC 地址 + 厂商识别
    info.mac = GetMACAddress(ip);
    if (!info.mac.empty()) {
        if (IsRandomMac(info.mac)) {
            info.vendor = L"随机MAC(隐私)";
            info.deviceType = L"移动设备?";
        } else {
            std::wstring vendor, type;
            if (LookupOUI(info.mac, vendor, type)) {
                info.vendor = vendor;
                info.deviceType = type;
            }
        }
    }

    // 2. 检测 SMB 端口
    info.hasSMB = CheckSMBPort(ip, 300);

    // 3. 反查主机名（手机通常无 NetBIOS / 反向 DNS，会失败，后续由 UA 上报补全）
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char hostBuf[NI_MAXHOST] = { 0 };
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostBuf, NI_MAXHOST, nullptr, 0, NI_NAMEREQD) == 0) {
        info.hostname = StringToWString(hostBuf);
        size_t dot = info.hostname.find(L'.');
        if (dot != std::wstring::npos) info.hostname = info.hostname.substr(0, dot);
    }

    // 4. 如果有 SMB，尝试获取 Windows OS 信息
    if (info.hasSMB) {
        if (info.deviceType.empty() || info.deviceType == L"其他" || info.deviceType == L"移动设备?")
            info.deviceType = L"Windows";
        std::wstring serverName = L"\\\\" + info.ip;
        SERVER_INFO_101* pSvr = nullptr;
        if (NetServerGetInfo((LMSTR)serverName.c_str(), 101, (LPBYTE*)&pSvr) == NERR_Success && pSvr) {
            info.osName = GetOSName(pSvr->sv101_version_major, pSvr->sv101_version_minor);
            if (info.hostname.empty() && pSvr->sv101_name) info.hostname = pSvr->sv101_name;
            NetApiBufferFree(pSvr);
        }
    }

    if (info.hostname.empty()) info.hostname = L"(未知)";
    if (info.osName.empty()) info.osName = info.hasSMB ? L"(未知)" : L"-";
    if (info.deviceType.empty()) info.deviceType = L"其他";
    if (info.vendor.empty()) info.vendor = L"(未知)";
    return info;
}

struct InfoReady { int row; uint64_t gen; DeviceInfo info; };
void FetchDeviceInfoThread(std::string ip, int row, uint64_t gen) {
    DeviceInfo info = GetDeviceInfo(ip);
    InfoReady* r = new InfoReady{ row, gen, info };
    PostMessageW(g_hWnd, WM_DEVICE_INFO_READY, 0, (LPARAM)r);
}

// ============== 多线程扫描（ping 为主，ARP 仅作待过滤的候选） ==============
struct ScanTask { std::string subnet; int start, end; };
struct RawHit { std::string ip; bool pingOk; std::string mac; };

void ScanWorker(const ScanTask& task, std::vector<RawHit>* outHits, std::mutex* outMtx) {
    for (int i = task.start; i <= task.end; i++) {
        if (!g_scanning) break;
        std::string ip = task.subnet + std::to_string(i);
        bool ok = PingHost(ip, 300);
        std::string mac;
        if (!ok) {
            // 仅记录 ARP 候选，是否可信交由扫描主线程结合网关/MAC频率统一判定（防代理ARP假阳性）
            std::wstring m = GetMACAddress(ip);
            if (!m.empty()) mac = WStringToString(m);
        }
        if (ok || !mac.empty()) {
            std::lock_guard<std::mutex> lk(*outMtx);
            outHits->push_back({ ip, ok, mac });
        }
        PostMessageW(g_hWnd, WM_SCAN_PROGRESS, (WPARAM)i, 0);
    }
}

void ScanLanThread() {
    std::vector<LocalAddr> addrs = EnumLocalIPs();
    std::wstring detail;
    std::string localIP = GetBestLocalIP(addrs, &detail);
    if (localIP.empty()) {
        PostLog(L"[扫描] 错误：未找到可用于局域网的真实网卡。");
        PostLog(L"[扫描] 检测到代理/VPN 的 TUN(fake-ip) 虚拟网卡（如 Clash/Mihomo 的 198.18 段）抢占了默认路由。");
        PostLog(L"[扫描] 请暂时关闭代理软件的 TUN/增强模式，确认电脑连着真实 WiFi/网线后再扫描。");
        PostMessageW(g_hWnd, WM_SCAN_DONE, 0, 0);
        return;
    }
    PostLog(L"[扫描] 选用网卡: " + detail);
    PostLog(L"[扫描] 本机 IP: " + StringToWString(localIP));

    // 列出全部候选地址，便于排查
    for (const auto& a : addrs) {
        std::wstring tag;
        if (a.ifType == IF_TYPE_ETHERNET_CSMACD) tag = L" [以太网]";
        else if (a.ifType == IF_TYPE_IEEE80211) tag = L" [WiFi]";
        else tag = L" [类型" + std::to_wstring(a.ifType) + L"]";
        tag += a.hasGateway ? L" [有网关]" : L" [无网关]";
        if (a.special) tag += L" [fake-ip/保留-忽略]";
        else if (IsCGNAT(a.ip)) tag += L" [CGNAT]";
        if (a.isVirtual) tag += L" [虚拟]";
        PostLog(L"[扫描]   候选地址 " + StringToWString(a.ip) + tag);
    }

    size_t lastDot = localIP.rfind('.');
    if (lastDot == std::string::npos) {
        PostLog(L"[扫描] 错误: 无法解析网段");
        PostMessageW(g_hWnd, WM_SCAN_DONE, 0, 0);
        return;
    }
    std::string subnet = localIP.substr(0, lastDot + 1);
    PostLog(L"[扫描] 网段: " + StringToWString(subnet) + L"0/24，扫描中...");
    g_foundDevices.clear();
    { std::lock_guard<std::mutex> lock(g_rowMutex); g_ipToRow.clear(); }
    { std::lock_guard<std::mutex> lock(g_mapMtx); g_deviceMap.clear(); }

    std::vector<RawHit> hits;
    std::mutex hitsMtx;

    const int NUM = 20;
    std::vector<std::thread> threads;
    int range = 254 / NUM;
    for (int t = 0; t < NUM; t++) {
        ScanTask task;
        task.subnet = subnet;
        task.start = t * range + 1;
        task.end = (t == NUM - 1) ? 254 : (t + 1) * range;
        threads.emplace_back(ScanWorker, task, &hits, &hitsMtx);
    }
    for (auto& th : threads) if (th.joinable()) th.join();

    // ===== 统一过滤代理 ARP 假阳性 =====
    std::string gwIP = GetDefaultGatewayIP();
    std::string gwMac;
    if (!gwIP.empty()) {
        gwMac = WStringToString(GetMACAddress(gwIP));
        std::transform(gwMac.begin(), gwMac.end(), gwMac.begin(),
            [](unsigned char c) { return (char)std::toupper(c); });
    }
    // 统计每个 MAC 被多少 IP 使用（代理 ARP 会让大量 IP 共用同一 MAC）
    std::unordered_map<std::string, int> macCount;
    for (const auto& h : hits)
        if (!h.pingOk && !h.mac.empty()) macCount[h.mac]++;

    std::vector<std::string> finalIPs;
    int droppedProxy = 0;
    for (const auto& h : hits) {
        if (h.pingOk) { finalIPs.push_back(h.ip); continue; }
        std::string mu = h.mac;
        std::transform(mu.begin(), mu.end(), mu.begin(),
            [](unsigned char c) { return (char)std::toupper(c); });
        if (!gwMac.empty() && mu == gwMac) { droppedProxy++; continue; } // 网关代答
        auto it = macCount.find(h.mac);
        if (it != macCount.end() && it->second >= 3) { droppedProxy++; continue; } // 代理ARP
        finalIPs.push_back(h.ip); // ping 不通但拥有独立、非网关 MAC 的真实设备
    }

    // 按最后一段数字排序
    std::sort(finalIPs.begin(), finalIPs.end(), [](const std::string& a, const std::string& b) {
        auto tail = [](const std::string& s) { int v = 0; size_t p = s.rfind('.');
            if (p != std::string::npos) v = atoi(s.c_str() + p + 1); return v; };
        return tail(a) < tail(b);
    });

    for (const auto& ip : finalIPs) {
        std::wstring ipW = StringToWString(ip);
        { std::lock_guard<std::mutex> lk(g_devicesMutex); g_foundDevices.push_back(ipW); }
        PostMessageW(g_hWnd, WM_DEVICE_FOUND, 0, (LPARAM)new std::wstring(ipW));
        PostLog(L"[扫描] 在线设备: " + ipW);
    }
    if (droppedProxy > 0)
        PostLog(L"[扫描] 已过滤 " + std::to_wstring(droppedProxy) +
            L" 个由路由器代理 ARP 产生的虚假地址（它们并非真实设备）");

    int count = (int)finalIPs.size();
    PostLog(L"[扫描] 完成，确认 " + std::to_wstring(count) + L" 台真实在线设备");
    PostMessageW(g_hWnd, WM_SCAN_DONE, (WPARAM)count, 0);
}

// ============== 简易线程池 ==============
class ThreadPool {
public:
    explicit ThreadPool(size_t n) {
        for (size_t i = 0; i < n; i++)
            workers.emplace_back([this] { Worker(); });
    }
    void Enqueue(std::function<void()> job) {
        {
            std::lock_guard<std::mutex> lk(m);
            tasks.push(std::move(job));
        }
        cv.notify_one();
    }
    void Shutdown() {
        {
            std::lock_guard<std::mutex> lk(m);
            stopping = true;
        }
        cv.notify_all();
        for (auto& w : workers) if (w.joinable()) w.join();
    }
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex m;
    std::condition_variable cv;
    bool stopping = false;
    void Worker() {
        while (true) {
            std::function<void()> job;
            {
                std::unique_lock<std::mutex> lk(m);
                cv.wait(lk, [this] { return stopping || !tasks.empty(); });
                if (stopping && tasks.empty()) return;
                job = std::move(tasks.front());
                tasks.pop();
            }
            try { job(); } catch (...) {}
        }
    }
};

// ============== HTTP 缓冲读取（避免逐字节系统调用） ==============
struct ClientCtx {
    SOCKET sock;
    std::vector<char> rbuf;
    size_t rpos = 0, rlen = 0;
    std::string front;
    explicit ClientCtx(SOCKET s) : sock(s), rbuf(8192) {}

    int ReadRaw(char* dst, int len) {
        int got = 0;
        if (!front.empty()) {
            int t = (std::min)(len, (int)front.size());
            memcpy(dst, front.data(), t);
            front.erase(0, t);
            got += t; dst += t; len -= t;
            if (len == 0) return got;
        }
        while (len > 0) {
            if (rpos >= rlen) {
                rpos = 0;
                int n = recv(sock, rbuf.data(), (int)rbuf.size(), 0);
                if (n <= 0) return got > 0 ? got : (n == 0 ? 0 : -1);
                rlen = n;
            }
            int t = (std::min)(len, (int)(rlen - rpos));
            memcpy(dst, rbuf.data() + rpos, t);
            rpos += t; got += t; dst += t; len -= t;
        }
        return got;
    }
    bool ReadLine(std::string& out) {
        out.clear();
        char c;
        while (true) {
            int n = ReadRaw(&c, 1);
            if (n <= 0) return !out.empty();
            if (c == '\n') {
                if (!out.empty() && out.back() == '\r') out.pop_back();
                return true;
            }
            out.push_back(c);
            if (out.size() > 65536) return false;
        }
    }
    void PushBack(const std::string& s) { front = s + front; }
};

// ============== HTTP 公共发送 ==============
bool SendRaw(SOCKET sock, const std::string& data) {
    const char* p = data.data();
    size_t left = data.size();
    while (left > 0) {
        int n = send(sock, p, (int)left, 0);
        if (n <= 0) return false;
        p += n; left -= n;
    }
    return true;
}
static void SendHeader(SOCKET s, int code, const std::string& contentType,
    int64_t contentLen, const std::string& extra = "") {
    std::string h = "HTTP/1.1 " + std::to_string(code) +
        (code == 200 ? " OK" : code == 204 ? " No Content" :
        code == 404 ? " Not Found" : code == 403 ? " Forbidden" : " Bad Request") + "\r\n";
    if (!contentType.empty()) h += "Content-Type: " + contentType + "\r\n";
    if (contentLen >= 0) h += "Content-Length: " + std::to_string(contentLen) + "\r\n";
    h += extra;
    h += "Connection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
    SendRaw(s, h);
}

// ============== URL 编解码 ==============
std::string UrlEncode(const std::string& str) {
    std::string result;
    for (unsigned char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            result += c;
        else { char b[4]; sprintf_s(b, "%%%02X", c); result += b; }
    }
    return result;
}
std::string UrlDecode(const std::string& str) {
    std::string result;
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int hex = 0;
            if (sscanf_s(str.c_str() + i + 1, "%2x", &hex) == 1) { result += (char)hex; i += 2; }
            else result += str[i];
        } else if (str[i] == '+') result += ' ';
        else result += str[i];
    }
    return result;
}

// ============== UserAgent 解析（识别手机品牌与型号） ==============
static bool IsVivoModel(const std::string& d) {
    // V + 3~4 位数字 + 可选字母，如 V2254A / V2005A
    if (d.size() < 4 || d[0] != 'V') return false;
    size_t i = 1, digits = 0;
    while (i < d.size() && std::isdigit((unsigned char)d[i])) { digits++; i++; }
    if (digits < 3) return false;
    if (i == d.size()) return true;
    if (i == d.size() - 1 && std::isalpha((unsigned char)d[i])) return true;
    return false;
}

void ParseUserAgent(const std::string& uaIn,
    std::wstring& brand, std::wstring& type, std::wstring& model, std::wstring& osVer) {
    std::string low = ToLower(uaIn);
    auto has = [&](const char* s) { return low.find(s) != std::string::npos; };
    brand = L""; type = L""; model = L""; osVer = L"";

    if (has("iphone")) {
        brand = L"Apple"; type = L"Apple(iPhone)"; model = L"iPhone";
        size_t p = low.find("iphone os ");
        if (p != std::string::npos) osVer = L"iOS " + StringToWString(uaIn.substr(p + 10, 3));
        return;
    }
    if (has("ipad")) { brand = L"Apple"; type = L"Apple(iPad)"; model = L"iPad"; return; }
    if (has("mac os x") || has("macintosh")) { brand = L"Apple"; type = L"Apple(Mac)"; model = L"Mac"; return; }
    if (has("windows")) { brand = L""; type = L"Windows"; model = L"Windows PC"; return; }

    if (has("android")) {
        // 系统版本
        size_t ap = low.find("android ");
        if (ap != std::string::npos) {
            std::string v;
            for (size_t i = ap + 8; i < uaIn.size() && (std::isdigit((unsigned char)uaIn[i]) || uaIn[i] == '.'); i++) v += uaIn[i];
            if (!v.empty()) osVer = L"Android " + StringToWString(v);
        }
        // 型号：第二个分号之后、Build/ 之前
        std::string dev;
        size_t s1 = uaIn.find(';', ap);
        size_t s2 = (s1 == std::string::npos) ? std::string::npos : uaIn.find(';', s1 + 1);
        if (s2 != std::string::npos) {
            size_t begin = s2 + 1;
            while (begin < uaIn.size() && uaIn[begin] == ' ') begin++;
            size_t bp = low.find("build/", begin);
            size_t end = (bp != std::string::npos) ? bp : uaIn.find(')', begin);
            if (end != std::string::npos) dev = Trim(uaIn.substr(begin, end - begin));
        }

        if (has("huawei")) brand = L"华为";
        else if (has("honor")) brand = L"荣耀";
        else if (has("redmi")) brand = L"小米(Redmi)";
        else if (has("xiaomi")) brand = L"小米";
        else if (has("oppo")) brand = L"OPPO";
        else if (has("realme")) brand = L"realme";
        else if (has("oneplus")) brand = L"一加";
        else if (has("iqoo")) brand = L"vivo(iQOO)";
        else if (has("vivo")) brand = L"vivo";
        else if (has("sm-") || has("samsung")) brand = L"三星";
        else if (dev.find("RMX") != std::string::npos) brand = L"realme";
        else if (IsVivoModel(dev)) brand = L"vivo";
        else brand = L"安卓设备";

        type = L"Android";
        model = StringToWString(dev);
        return;
    }
    type = L"其他";
    model = L"未知设备";
}

std::string GetPeerIP(SOCKET s) {
    sockaddr_in a = { 0 }; int len = sizeof(a);
    if (getpeername(s, (sockaddr*)&a, &len) == 0) {
        char tmp[INET_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET, &a.sin_addr, tmp, sizeof(tmp));
        return tmp;
    }
    return "";
}

// 简易 JSON 字符串字段提取
std::string GetJsonString(const std::string& j, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return "";
    p = j.find(':', p + pat.size());
    if (p == std::string::npos) return "";
    p = j.find('"', p + 1);
    if (p == std::string::npos) return "";
    std::string out;
    for (size_t i = p + 1; i < j.size(); i++) {
        char c = j[i];
        if (c == '\\' && i + 1 < j.size()) {
            char n = j[++i];
            switch (n) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'n': out += '\n'; break;
            case 't': out += '\t'; break;
            case 'u':
                if (i + 4 < j.size()) i += 4;
                break;
            default: out += n;
            }
        } else if (c == '"') break;
        else out += c;
    }
    return out;
}

struct UAReport {
    std::wstring ip, brand, type, osVer, model;
};

// ============== multipart 流式扫描到定界符 ==============
bool ScanToMarker(ClientCtx& ctx, const std::string& marker,
    const std::function<void(const char*, size_t)>& cb, std::string& restOut) {
    std::string carry;
    char chunk[65536];
    while (true) {
        int n = ctx.ReadRaw(chunk, sizeof(chunk));
        if (n <= 0) {
            if (!carry.empty() && cb) cb(carry.data(), carry.size());
            return false;
        }
        std::string data = carry;
        data.append(chunk, n);
        size_t idx = data.find(marker);
        if (idx != std::string::npos) {
            if (idx && cb) cb(data.data(), idx);
            restOut = data.substr(idx + marker.size());
            return true;
        }
        size_t keep = (std::min)(data.size(), marker.size() - 1);
        if ((data.size() - keep) && cb) cb(data.data(), data.size() - keep);
        carry.assign(data, data.size() - keep, keep);
    }
}

bool ReadBoundaryLine(ClientCtx& ctx, const std::string& startDash, bool& isEnd) {
    std::string line;
    while (ctx.ReadLine(line)) {
        if (line.empty()) continue;
        if (line.compare(0, startDash.size(), startDash) != 0) return false;
        std::string tail = line.substr(startDash.size());
        isEnd = (tail.find("--") != std::string::npos);
        return true;
    }
    return false;
}

// ============== HTTP 客户端处理 ==============
void HandleHttpClient(SOCKET clientSock) {
    // RAII：登记/注销活跃连接并负责关闭
    struct Guard {
        SOCKET s;
        Guard(SOCKET x) : s(x) { std::lock_guard<std::mutex> lk(g_activeMtx); g_activeClients.insert(s); }
        ~Guard() { { std::lock_guard<std::mutex> lk(g_activeMtx); g_activeClients.erase(s); } closesocket(s); }
    } guard(clientSock);

    DWORD timeout = 15000;
    setsockopt(clientSock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(clientSock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    ClientCtx ctx(clientSock);
    std::string requestLine;
    if (!ctx.ReadLine(requestLine) || requestLine.empty()) return;

    std::string method, path;
    size_t sp1 = requestLine.find(' ');
    if (sp1 != std::string::npos) {
        method = requestLine.substr(0, sp1);
        size_t sp2 = requestLine.find(' ', sp1 + 1);
        if (sp2 != std::string::npos) path = requestLine.substr(sp1 + 1, sp2 - sp1 - 1);
    }

    int contentLength = 0;
    std::string contentType;
    bool expectContinue = false;
    std::string line;
    while (ctx.ReadLine(line)) {
        if (line.empty()) break;
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = ToLower(line.substr(0, colon));
            std::string val = Trim(line.substr(colon + 1));
            if (key == "content-length") contentLength = atoi(val.c_str());
            else if (key == "content-type") contentType = val;
            else if (key == "expect" && ToLower(val).find("100-continue") != std::string::npos) expectContinue = true;
        }
    }

    std::wstring sharePath = g_httpSharePath;
    if (sharePath.empty()) sharePath = g_selectedPath;

    // 去掉路径中可能的查询（除 download 外）
    std::string pathNoQ = path;
    size_t qm = path.find('?');
    if (qm != std::string::npos && path.find("/download") != 0) pathNoQ = path.substr(0, qm);

    // ===== favicon：快速 204，避免无谓 404 =====
    if (method == "GET" && (pathNoQ == "/favicon.ico")) {
        SendHeader(clientSock, 204, "", 0);
        return;
    }

    // ===== GET / 文件列表 + 上传表单 =====
    if (method == "GET" && (pathNoQ == "/" || pathNoQ == "/index.html")) {
        std::string html = "<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
        html += "<title>文件传输</title><style>";
        html += "body{font-family:-apple-system,sans-serif;margin:16px;background:#f0f2f5}";
        html += ".card{background:#fff;border-radius:12px;padding:16px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.08)}";
        html += "h2{margin:0 0 12px;font-size:18px;color:#333}";
        html += ".file{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #eee}";
        html += ".file:last-child{border-bottom:none}";
        html += ".fname{color:#1a73e8;text-decoration:none;font-size:15px;word-break:break-all;flex:1}";
        html += ".fsize{color:#999;font-size:13px;margin-left:12px;white-space:nowrap}";
        html += "input[type=file]{width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;margin-bottom:10px;font-size:14px}";
        html += "button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600}";
        html += "button:active{background:#1557b0}";
        html += ".empty{color:#999;text-align:center;padding:20px;font-size:14px}";
        html += ".tip{color:#888;font-size:12px;text-align:center;margin-top:16px}";
        html += "</style></head><body>";

        html += "<div class='card'><h2>\U0001F4E4 上传文件到电脑</h2>";
        html += "<form action='/upload' method='post' enctype='multipart/form-data'>";
        html += "<input type='file' name='file' multiple>";
        html += "<button type='submit'>上传</button></form></div>";

        html += "<div class='card'><h2>\U0001F4E5 电脑共享文件</h2>";
        std::error_code ec;
        bool hasFile = false;
        if (fs::is_directory(sharePath, ec)) {
            for (const auto& entry : fs::recursive_directory_iterator(sharePath, ec)) {
                if (!entry.is_regular_file()) continue;
                hasFile = true;
                fs::path rel = entry.path().lexically_relative(sharePath);
                std::string relUtf8 = WStringToString(rel.wstring());
                std::string nameUtf8 = WStringToString(entry.path().filename().wstring());
                uintmax_t fsize = entry.file_size(ec);
                char sz[64];
                if (fsize > 1048576) sprintf_s(sz, "%.1f MB", fsize / 1048576.0);
                else if (fsize > 1024) sprintf_s(sz, "%.1f KB", fsize / 1024.0);
                else sprintf_s(sz, "%llu B", (unsigned long long)fsize);
                html += "<div class='file'><a class='fname' href='/download?path=" + UrlEncode(relUtf8) + "'>" + nameUtf8 + "</a><span class='fsize'>" + sz + "</span></div>";
            }
        } else if (fs::is_regular_file(sharePath, ec)) {
            hasFile = true;
            std::string nameUtf8 = WStringToString(fs::path(sharePath).filename().wstring());
            uintmax_t fsize = fs::file_size(sharePath, ec);
            char sz[64];
            if (fsize > 1048576) sprintf_s(sz, "%.1f MB", fsize / 1048576.0);
            else sprintf_s(sz, "%.1f KB", fsize / 1024.0);
            html += "<div class='file'><a class='fname' href='/download?path=.'>" + nameUtf8 + "</a><span class='fsize'>" + sz + "</span></div>";
        }
        if (!hasFile) html += "<p class='empty'>电脑端尚未选择共享文件</p>";
        html += "</div>";
        html += "<p class='tip'>局域网文件传输工具 · 手机浏览器访问</p>";

        // 打开页面即上报设备信息（品牌/型号）
        html += "<script>(function(){try{var i={ua:navigator.userAgent,plat:navigator.platform,"
                "lang:navigator.language,sw:screen.width,sh:screen.height};"
                "fetch('/api/report',{method:'POST',headers:{'Content-Type':'application/json'},"
                "body:JSON.stringify(i)}).catch(function(){});}catch(e){}})();</script>";
        html += "</body></html>";

        SendHeader(clientSock, 200, "text/html; charset=utf-8", (int64_t)html.size());
        SendRaw(clientSock, html);
        return;
    }

    // ===== GET /download 下载文件 =====
    if (method == "GET" && path.find("/download") == 0) {
        fs::path filePath;
        size_t qp = path.find("?path=");
        if (qp != std::string::npos) {
            std::string param = UrlDecode(path.substr(qp + 6));
            if (param == ".") {
                filePath = fs::path(sharePath);
            } else {
                std::wstring paramW = StringToWString(param);
                filePath = fs::path(sharePath) / fs::path(paramW);
            }
        }

        // 路径安全：规范化并确保仍位于共享目录内（防 ../ 穿越）
        std::error_code ec;
        fs::path base = fs::is_directory(sharePath, ec) ?
            fs::canonical(sharePath, ec) : fs::canonical(sharePath, ec).parent_path();
        fs::path target = fs::exists(filePath, ec) ? fs::canonical(filePath, ec) : filePath.lexically_normal();
        std::wstring tb = target.wstring(), bb = base.wstring();
        bool inside = (_wcsicmp(tb.c_str(), bb.c_str()) == 0) ||
            (tb.size() > bb.size() && _wcsnicmp(tb.c_str(), bb.c_str(), bb.size()) == 0 &&
                (tb[bb.size()] == L'\\' || tb[bb.size()] == L'/'));

        std::ifstream file(target, std::ios::binary | std::ios::ate);
        if (!inside || !file.is_open()) {
            std::string body = "File not found / forbidden";
            SendHeader(clientSock, 404, "text/plain; charset=utf-8", (int64_t)body.size());
            SendRaw(clientSock, body);
            return;
        }

        int64_t fsize = (int64_t)file.tellg();
        file.seekg(0, std::ios::beg);
        std::string fnameUtf8 = WStringToString(target.filename().wstring());
        std::string fnameEncoded = UrlEncode(fnameUtf8);
        std::string extra = "Content-Disposition: attachment; filename*=UTF-8''" + fnameEncoded + "\r\n";
        SendHeader(clientSock, 200, "application/octet-stream", fsize, extra);

        const int BUF = 65536;
        std::vector<char> buf(BUF);
        bool fail = false;
        while (file.read(buf.data(), BUF) || file.gcount() > 0) {
            if (!SendRaw(clientSock, std::string(buf.data(), file.gcount()))) { fail = true; break; }
        }
        file.close();
        if (!fail) PostLog(L"[HTTP] 下载: " + target.filename().wstring());
        return;
    }

    // ===== POST /api/report 手机品牌型号上报 =====
    if (method == "POST" && pathNoQ == "/api/report") {
        std::string body;
        if (contentLength > 0 && contentLength < 16384) {
            body.resize(contentLength);
            int total = 0;
            while (total < contentLength) {
                int n = ctx.ReadRaw(body.data() + total, contentLength - total);
                if (n <= 0) break;
                total += n;
            }
        }
        std::string ua = GetJsonString(body, "ua");
        std::string peer = GetPeerIP(clientSock);
        if (!ua.empty() && !peer.empty()) {
            std::wstring brand, type, model, osVer;
            ParseUserAgent(ua, brand, type, model, osVer);
            UAReport* r = new UAReport{ StringToWString(peer), brand, type, osVer, model };
            PostMessageW(g_hWnd, WM_UA_REPORT, 0, (LPARAM)r);
        }
        std::string resp = "{\"ok\":1}";
        SendHeader(clientSock, 200, "application/json; charset=utf-8", (int64_t)resp.size());
        SendRaw(clientSock, resp);
        return;
    }

    // ===== POST /upload 流式接收上传文件 =====
    if (method == "POST" && path.find("/upload") == 0) {
        size_t bp = contentType.find("boundary=");
        if (bp == std::string::npos) {
            std::string b = "Bad Request: no boundary";
            SendHeader(clientSock, 400, "text/plain; charset=utf-8", (int64_t)b.size());
            SendRaw(clientSock, b);
            return;
        }
        std::string boundary = contentType.substr(bp + 9);
        // 去掉 boundary 可能带的引号
        if (!boundary.empty() && boundary.front() == '"') boundary.erase(boundary.begin());
        if (!boundary.empty() && boundary.back() == '"') boundary.pop_back();

        std::string startDash = "--" + boundary;
        std::string marker = "\r\n--" + boundary;

        if (expectContinue)
            SendRaw(clientSock, "HTTP/1.1 100 Continue\r\n\r\n");

        bool isEnd = false;
        if (!ReadBoundaryLine(ctx, startDash, isEnd)) {
            std::string b = "Bad Request: malformed multipart";
            SendHeader(clientSock, 400, "text/plain; charset=utf-8", (int64_t)b.size());
            SendRaw(clientSock, b);
            return;
        }

        int savedCount = 0;
        while (!isEnd) {
            // 读取 part 头部
            std::string filename, partLine;
            while (ctx.ReadLine(partLine)) {
                if (partLine.empty()) break;
                size_t fnp = partLine.find("filename=\"");
                if (fnp != std::string::npos) {
                    size_t fne = partLine.find("\"", fnp + 10);
                    if (fne != std::string::npos)
                        filename = partLine.substr(fnp + 10, fne - fnp - 10);
                }
            }

            std::string rest;
            if (filename.empty()) {
                // 普通字段，丢弃内容
                if (!ScanToMarker(ctx, marker, nullptr, rest)) break;
            } else {
                std::wstring wfilename = StringToWString(UrlDecode(filename));
                fs::path base = fs::path(g_httpRecvDir) / fs::path(wfilename).filename();
                fs::path savePath = base;
                std::error_code ec;
                if (fs::exists(savePath, ec)) {
                    int idx = 1;
                    fs::path stem = base.stem(), ext = base.extension();
                    while (fs::exists(fs::path(g_httpRecvDir) /
                        (stem.wstring() + L"_" + std::to_wstring(idx) + ext.wstring()), ec)) idx++;
                    savePath = fs::path(g_httpRecvDir) /
                        (stem.wstring() + L"_" + std::to_wstring(idx) + ext.wstring());
                }
                std::ofstream out(savePath, std::ios::binary);
                bool ok = false;
                if (out.is_open()) {
                    ok = ScanToMarker(ctx, marker,
                        [&](const char* d, size_t l) { out.write(d, l); }, rest);
                    out.close();
                }
                if (ok) {
                    savedCount++;
                    PostLog(L"[HTTP] 上传接收: " + savePath.filename().wstring() +
                        L" (" + std::to_wstring(fs::file_size(savePath, ec)) + L" 字节)");
                } else {
                    std::error_code e2; fs::remove(savePath, e2);
                    break;
                }
            }

            if (rest.compare(0, 2, "--") == 0) {
                isEnd = true;
            } else {
                ctx.PushBack(rest);
                bool dummy = false;
                if (!ReadBoundaryLine(ctx, startDash, isEnd)) break;
                (void)dummy;
            }
        }

        std::string html = "<html><head><meta charset='utf-8'><meta http-equiv='refresh' content='2;url=/'>";
        html += "<title>上传完成</title></head><body style='font-family:sans-serif;text-align:center;padding:40px'>";
        html += "<h2 style='color:#34a853'>\u2705 上传完成</h2><p>已保存 " + std::to_string(savedCount) + " 个文件到电脑</p>";
        html += "<p>2秒后自动返回...</p></body></html>";
        SendHeader(clientSock, 200, "text/html; charset=utf-8", (int64_t)html.size());
        SendRaw(clientSock, html);
        return;
    }

    // ===== 其它：404 =====
    std::string body = "Not Found";
    SendHeader(clientSock, 404, "text/plain; charset=utf-8", (int64_t)body.size());
    SendRaw(clientSock, body);
}

// ============== HTTP 服务器线程 ==============
void HttpServerThread(int port) {
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) { PostLog(L"[HTTP] 创建socket失败"); g_httpRunning = false; return; }
    BOOL opt = TRUE;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((u_short)port);
    if (bind(listenSock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        PostLog(L"[HTTP] 绑定端口 " + std::to_wstring(port) + L" 失败（可能被占用）");
        closesocket(listenSock); g_httpSock = INVALID_SOCKET; g_httpRunning = false; return;
    }
    listen(listenSock, SOMAXCONN);
    g_httpSock = listenSock;

    PostLog(L"[HTTP] 服务已启动，端口 " + std::to_wstring(port));

    std::vector<LocalAddr> addrs = EnumLocalIPs();
    // 首选地址
    std::string best = GetBestLocalIP(addrs);
    if (best.empty()) {
        PostLog(L"[HTTP] 警告：未识别到真实局域网网卡（可能开启了代理 TUN 模式）。服务虽已启动，手机可能无法访问。");
        PostLog(L"[HTTP] 请关闭代理软件的 TUN/增强模式后重新启动服务。");
    } else {
        std::wstring url = L"http://" + StringToWString(best) + L":" + std::to_wstring(port);
        PostMessageW(g_hWnd, WM_HTTP_UPDATE, 0, (LPARAM)new std::wstring(url));
    }
    PostLog(L"[HTTP] 手机连同一 WiFi，用浏览器访问以下地址：");
    for (const auto& a : addrs) {
        if (a.special || a.isVirtual) continue; // 只列真实网卡
        std::wstring u = L"    http://" + StringToWString(a.ip) + L":" + std::to_wstring(port) +
            (a.ip == best ? L"   <== 首选" : L"");
        PostLog(u);
    }
    PostLog(L"[HTTP] 打开页面后会自动识别手机品牌与型号；页面可上传/下载文件。");

    ThreadPool pool(32);
    while (g_httpRunning) {
        fd_set readSet; FD_ZERO(&readSet); FD_SET(listenSock, &readSet);
        struct timeval tv = { 1, 0 };
        if (select(0, &readSet, nullptr, nullptr, &tv) <= 0) continue;
        if (!g_httpRunning) break;
        SOCKET client = accept(listenSock, nullptr, nullptr);
        if (client != INVALID_SOCKET) {
            { std::lock_guard<std::mutex> lk(g_activeMtx); g_activeClients.insert(client); }
            pool.Enqueue([client] { HandleHttpClient(client); });
        }
    }

    // 唤醒所有正在处理的连接，让其立即结束
    {
        std::lock_guard<std::mutex> lk(g_activeMtx);
        for (SOCKET s : g_activeClients) shutdown(s, SD_BOTH);
    }
    pool.Shutdown();
    if (g_httpSock != INVALID_SOCKET) { closesocket(g_httpSock); g_httpSock = INVALID_SOCKET; }
    PostLog(L"[HTTP] 服务已停止");
}

void StopHttpServer() {
    if (!g_httpRunning && !g_httpThread.joinable()) return;
    g_httpRunning = false;
    if (g_httpSock != INVALID_SOCKET) shutdown(g_httpSock, SD_BOTH);
    {
        std::lock_guard<std::mutex> lk(g_activeMtx);
        for (SOCKET s : g_activeClients) shutdown(s, SD_BOTH);
    }
    if (g_httpThread.joinable()) g_httpThread.join();
    g_httpSock = INVALID_SOCKET;

    EnableWindow(g_hBtnHttpStart, TRUE);
    EnableWindow(g_hBtnHttpStop, FALSE);
    EnableWindow(g_hBtnOpenUrl, FALSE);
    SetWindowTextW(g_hStaticHttpUrl, L"已停止");
}

// ============== SMB 文件传输 ==============
bool ConnectSMB(const std::wstring& ip, const std::wstring& share, const std::wstring& user, const std::wstring& pass) {
    std::wstring remote = L"\\\\" + ip + L"\\" + share;
    NETRESOURCE nr = { 0 };
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = (LPWSTR)remote.c_str();
    LPCWSTR pUser = user.empty() ? nullptr : user.c_str();
    LPCWSTR pPass = pass.empty() ? nullptr : pass.c_str();
    DWORD ret = WNetAddConnection2(&nr, (LPWSTR)pPass, (LPWSTR)pUser, CONNECT_TEMPORARY);
    if (ret == NO_ERROR) return true;
    if (ret == ERROR_ACCESS_DENIED || ret == ERROR_LOGON_FAILURE) {
        ret = WNetAddConnection2(&nr, nullptr, nullptr, CONNECT_TEMPORARY);
        if (ret == NO_ERROR) return true;
    }
    return false;
}
void DisconnectSMB(const std::wstring& ip, const std::wstring& share) {
    WNetCancelConnection2((L"\\\\" + ip + L"\\" + share).c_str(), 0, TRUE);
}
bool CopySingleFile(const std::wstring& local, const std::wstring& remote) {
    std::wstring dir = remote.substr(0, remote.rfind(L'\\'));
    SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return CopyFileW(local.c_str(), remote.c_str(), FALSE) == TRUE;
}
struct SendResult { std::wstring ip; bool success; std::wstring message; };
SendResult SendFilesToDevice(const std::wstring& ip, const std::wstring& localPath,
    const std::wstring& share, const std::wstring& subDir, const std::wstring& user, const std::wstring& pass) {
    SendResult r; r.ip = ip; r.success = false;
    if (!ConnectSMB(ip, share, user, pass)) { r.message = L"SMB连接失败"; return r; }
    try {
        std::wstring base = L"\\\\" + ip + L"\\" + share;
        if (!subDir.empty()) base += L"\\" + subDir;
        std::error_code ec; int cnt = 0, fail = 0;
        if (fs::is_directory(localPath, ec)) {
            fs::path bp(localPath);
            for (const auto& e : fs::recursive_directory_iterator(localPath, ec)) {
                if (!e.is_regular_file()) continue;
                fs::path rel = e.path().lexically_relative(bp);
                if (CopySingleFile(e.path().wstring(), base + L"\\" + rel.wstring())) cnt++; else fail++;
            }
        } else {
            if (CopySingleFile(localPath, base + L"\\" + fs::path(localPath).filename().wstring())) cnt++; else fail++;
        }
        r.success = (fail == 0 && cnt > 0);
        r.message = L"成功" + std::to_wstring(cnt) + L"个" + (fail ? L"失败" + std::to_wstring(fail) + L"个" : L"");
    }
    catch (...) { r.message = L"异常"; }
    DisconnectSMB(ip, share);
    return r;
}

void SendToAllThread(std::wstring path, std::wstring share, std::wstring subDir, std::wstring user, std::wstring pass) {
    std::vector<std::wstring> devs;
    { std::lock_guard<std::mutex> l(g_devicesMutex); devs = g_foundDevices; }
    if (devs.empty()) { PostLog(L"[发送] 无在线设备"); g_sending = false; return; }
    int ok = 0, fail = 0;
    for (const auto& ip : devs) {
        PostLog(L"[发送] -> " + ip);
        SendResult r = SendFilesToDevice(ip, path, share, subDir, user, pass);
        if (r.success) { ok++; PostLog(L"[发送] " + ip + L": " + r.message); }
        else { fail++; PostLog(L"[发送] " + ip + L": " + r.message + L" (手机/非Windows设备请用HTTP下载)"); }
    }
    PostLog(L"[发送] 完成: 成功" + std::to_wstring(ok) + L"台 失败" + std::to_wstring(fail) + L"台");
    PostMessageW(g_hWnd, WM_STATUS_UPDATE, 0, (LPARAM)new std::wstring(L"发送完成"));
    g_sending = false;
}

// 修复：单设备 SMB 推送（原代码未实现且会把 g_sending 永久卡死）
void SendToOneThread(std::wstring ip, std::wstring path,
    std::wstring share, std::wstring sub, std::wstring user, std::wstring pass) {
    PostLog(L"[发送] -> " + ip);
    SendResult r = SendFilesToDevice(ip, path, share, sub, user, pass);
    if (r.success) PostLog(L"[发送] " + ip + L": " + r.message);
    else PostLog(L"[发送] " + ip + L": " + r.message + L" (手机/非Windows设备请用HTTP下载)");
    PostMessageW(g_hWnd, WM_STATUS_UPDATE, 0,
        (LPARAM)new std::wstring(r.success ? L"发送完成" : L"发送失败"));
    g_sending = false;
}

// ============== 文件选择 ==============
bool BrowseForFile(HWND h, std::wstring& out) {
    OPENFILENAMEW ofn = { 0 }; wchar_t f[MAX_PATH] = { 0 };
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = h;
    ofn.lpstrFilter = L"所有文件 (*.*)\0*.*\0"; ofn.lpstrFile = f; ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) { out = f; return true; }
    return false;
}
bool BrowseForDir(HWND h, std::wstring& out) {
    BROWSEINFOW bi = { 0 }; bi.hwndOwner = h; bi.lpszTitle = L"选择文件夹";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        wchar_t p[MAX_PATH] = { 0 };
        if (SHGetPathFromIDListW(pidl, p)) { out = p; CoTaskMemFree(pidl); return true; }
        CoTaskMemFree(pidl);
    }
    return false;
}
void ParseSharePath(const std::wstring& in, std::wstring& share, std::wstring& sub) {
    share.clear(); sub.clear(); if (in.empty()) return;
    std::wstring c = in;
    while (!c.empty() && c.front() == L'\\') c.erase(c.begin());
    size_t p = c.find(L'\\');
    if (p == std::string::npos) share = c;
    else { share = c.substr(0, p); sub = c.substr(p + 1); }
}

// ============== ListView ==============
int ListViewAddDevice(const std::wstring& ip) {
    int row = ListView_GetItemCount(g_hListDevices);
    LVITEMW lvi = { 0 }; lvi.mask = LVIF_TEXT; lvi.iItem = row; lvi.iSubItem = 0;
    lvi.pszText = const_cast<LPWSTR>(ip.c_str());
    ListView_InsertItem(g_hListDevices, &lvi);
    ListView_SetItemText(g_hListDevices, row, 1, const_cast<LPWSTR>(L"解析中..."));
    ListView_SetItemText(g_hListDevices, row, 2, const_cast<LPWSTR>(L"-"));
    ListView_SetItemText(g_hListDevices, row, 3, const_cast<LPWSTR>(L"解析中..."));
    ListView_SetItemText(g_hListDevices, row, 4, const_cast<LPWSTR>(L"-"));
    ListView_SetItemText(g_hListDevices, row, 5, const_cast<LPWSTR>(L"在线"));
    return row;
}
void ListViewUpdateDevice(int row, const DeviceInfo& info) {
    ListView_SetItemText(g_hListDevices, row, 1, const_cast<LPWSTR>(info.hostname.c_str()));
    ListView_SetItemText(g_hListDevices, row, 2, const_cast<LPWSTR>(info.deviceType.c_str()));
    ListView_SetItemText(g_hListDevices, row, 3, const_cast<LPWSTR>(info.osName.c_str()));
    ListView_SetItemText(g_hListDevices, row, 4, const_cast<LPWSTR>(info.mac.empty() ? L"-" : info.mac.c_str()));
    ListView_SetItemText(g_hListDevices, row, 5, const_cast<LPWSTR>(info.hasSMB ? L"SMB可用" : L"HTTP浏览器"));
    PostLog(L"[设备] " + info.ip + L" | " + info.hostname + L" | " + info.deviceType +
        L" | " + info.vendor + L" | " + info.osName);
}

// ============== 窗口过程 ==============
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hf = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        CreateWindowW(L"STATIC", L"【设备扫描】", WS_CHILD | WS_VISIBLE, 10, 5, 100, 22, hWnd, 0, g_hInst, 0);
        g_hBtnScan = CreateWindowW(L"BUTTON", L"扫描局域网", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 110, 3, 100, 26, hWnd, (HMENU)IDC_BTN_SCAN, g_hInst, 0);
        g_hCheckAutoSend = CreateWindowW(L"BUTTON", L"扫描后自动SMB推送", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 215, 5, 140, 22, hWnd, (HMENU)IDC_CHECK_AUTOSEND, g_hInst, 0);
        g_hStaticScanInfo = CreateWindowW(L"STATIC", L"等待扫描", WS_CHILD | WS_VISIBLE | SS_RIGHT, 430, 5, 170, 22, hWnd, (HMENU)IDC_STATIC_SCANINFO, g_hInst, 0);
        CreateWindowW(L"STATIC", L"在线设备(双击选中):", WS_CHILD | WS_VISIBLE, 10, 32, 180, 18, hWnd, 0, g_hInst, 0);
        g_hListDevices = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 10, 52, 590, 110, hWnd, (HMENU)IDC_LIST_DEVICES, g_hInst, 0);
        ListView_SetExtendedListViewStyle(g_hListDevices, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        LVCOLUMNW lvc = { 0 }; lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; lvc.fmt = LVCFMT_LEFT;
        static const wchar_t* hdrs[] = { L"IP地址", L"主机名/型号", L"设备类型", L"操作系统", L"MAC地址", L"传输方式" };
        int wd[] = { 110, 130, 90, 110, 130, 80 };
        for (int i = 0; i < 6; i++) {
            lvc.iSubItem = i; lvc.pszText = const_cast<LPWSTR>(hdrs[i]);
            lvc.cx = wd[i]; ListView_InsertColumn(g_hListDevices, i, &lvc);
        }

        // HTTP 区域
        CreateWindowW(L"STATIC", L"【HTTP文件共享 - 手机浏览器访问】", WS_CHILD | WS_VISIBLE, 10, 168, 280, 20, hWnd, 0, g_hInst, 0);
        CreateWindowW(L"STATIC", L"端口:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 10, 190, 40, 18, hWnd, 0, g_hInst, 0);
        g_hEditHttpPort = CreateWindowW(L"EDIT", L"8080", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER, 55, 188, 60, 24, hWnd, (HMENU)IDC_EDIT_HTTPPORT, g_hInst, 0);
        g_hBtnHttpStart = CreateWindowW(L"BUTTON", L"启动服务", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 120, 187, 80, 26, hWnd, (HMENU)IDC_BTN_HTTPSTART, g_hInst, 0);
        g_hBtnHttpStop = CreateWindowW(L"BUTTON", L"停止服务", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED, 205, 187, 80, 26, hWnd, (HMENU)IDC_BTN_HTTPSTOP, g_hInst, 0);
        g_hStaticHttpUrl = CreateWindowW(L"STATIC", L"未启动", WS_CHILD | WS_VISIBLE | SS_LEFT, 290, 190, 215, 18, hWnd, (HMENU)IDC_STATIC_HTTPURL, g_hInst, 0);
        g_hBtnOpenUrl = CreateWindowW(L"BUTTON", L"打开页面", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED, 510, 187, 90, 26, hWnd, (HMENU)IDC_BTN_OPENURL, g_hInst, 0);

        // 文件选择
        CreateWindowW(L"STATIC", L"【要共享/发送的文件或目录】", WS_CHILD | WS_VISIBLE, 10, 218, 200, 20, hWnd, 0, g_hInst, 0);
        g_hEditFilePath = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 10, 240, 400, 24, hWnd, (HMENU)IDC_EDIT_FILEPATH, g_hInst, 0);
        g_hBtnSelFile = CreateWindowW(L"BUTTON", L"选择文件", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 415, 239, 85, 26, hWnd, (HMENU)IDC_BTN_SELFILE, g_hInst, 0);
        g_hBtnSelDir = CreateWindowW(L"BUTTON", L"选择目录", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 505, 239, 95, 26, hWnd, (HMENU)IDC_BTN_SELDIR, g_hInst, 0);

        // SMB 设置
        CreateWindowW(L"STATIC", L"SMB共享路径:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 10, 272, 90, 18, hWnd, 0, g_hInst, 0);
        g_hEditShare = CreateWindowW(L"EDIT", L"Users\\Public\\Downloads", WS_CHILD | WS_VISIBLE | WS_BORDER, 105, 270, 200, 24, hWnd, (HMENU)IDC_EDIT_SHARE, g_hInst, 0);
        CreateWindowW(L"STATIC", L"用户:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 310, 272, 40, 18, hWnd, 0, g_hInst, 0);
        g_hEditUser = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER, 355, 270, 80, 24, hWnd, (HMENU)IDC_EDIT_USER, g_hInst, 0);
        CreateWindowW(L"STATIC", L"密码:", WS_CHILD | WS_VISIBLE | SS_RIGHT, 440, 272, 35, 18, hWnd, 0, g_hInst, 0);
        g_hEditPass = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD, 480, 270, 60, 24, hWnd, (HMENU)IDC_EDIT_PASS, g_hInst, 0);
        g_hBtnSendOne = CreateWindowW(L"BUTTON", L"SMB推送到选中设备", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 10, 300, 200, 28, hWnd, (HMENU)IDC_BTN_SENDONE, g_hInst, 0);
        g_hBtnSendAll = CreateWindowW(L"BUTTON", L"SMB推送到所有Windows设备", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 220, 300, 220, 28, hWnd, (HMENU)IDC_BTN_SENDALL, g_hInst, 0);

        // 日志
        CreateWindowW(L"STATIC", L"【运行日志】", WS_CHILD | WS_VISIBLE, 10, 335, 100, 18, hWnd, 0, g_hInst, 0);
        g_hEditLog = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 10, 355, 590, 145, hWnd, (HMENU)IDC_EDIT_LOG, g_hInst, 0);
        g_hStaticStatus = CreateWindowW(L"STATIC", L"就绪", WS_CHILD | WS_VISIBLE | SS_LEFT, 10, 505, 590, 18, hWnd, (HMENU)IDC_STATIC_STATUS, g_hInst, 0);

        EnumChildWindows(hWnd, [](HWND c, LPARAM l) -> BOOL {
            SendMessageW(c, WM_SETFONT, (WPARAM)l, TRUE); return TRUE;
        }, (LPARAM)hf);

        Log(L"程序已启动。");
        Log(L"Windows电脑: 扫描后用SMB推送 | 手机(安卓/iOS): 启动HTTP服务后用浏览器访问，自动识别品牌型号");
        Log(L"使用步骤: 1.选择文件/目录 2.启动HTTP服务 3.手机连同一WiFi并打开页面地址");
        break;
    }
    case WM_LOG_MSG: {
        std::wstring* p = (std::wstring*)lParam;
        if (p) { Log(*p); delete p; }
        break;
    }
    case WM_DEVICE_FOUND: {
        std::wstring* p = (std::wstring*)lParam;
        if (p) {
            int row = ListViewAddDevice(*p);
            { std::lock_guard<std::mutex> l(g_rowMutex); g_ipToRow[*p] = row; }
            std::thread(FetchDeviceInfoThread, WStringToString(*p), row, g_scanGen.load()).detach();
            delete p;
        }
        break;
    }
    case WM_DEVICE_INFO_READY: {
        InfoReady* r = (InfoReady*)lParam;
        if (r) {
            if (r->gen == g_scanGen.load()) {
                if (r->row < ListView_GetItemCount(g_hListDevices))
                    ListViewUpdateDevice(r->row, r->info);
                { std::lock_guard<std::mutex> l(g_mapMtx); g_deviceMap[r->info.ip] = r->info; }
            }
            delete r;
        }
        break;
    }
    case WM_UA_REPORT: {
        UAReport* rep = (UAReport*)lParam;
        if (rep) {
            int row = -1;
            {
                std::lock_guard<std::mutex> l(g_rowMutex);
                auto it = g_ipToRow.find(rep->ip);
                if (it != g_ipToRow.end()) row = it->second;
            }
            if (row < 0) {
                // 扫描未发现但主动访问的 HTTP 客户端，动态加入
                row = ListViewAddDevice(rep->ip);
                { std::lock_guard<std::mutex> l(g_rowMutex); g_ipToRow[rep->ip] = row; }
                { std::lock_guard<std::mutex> l(g_devicesMutex); g_foundDevices.push_back(rep->ip); }
            }
            // 合并旧信息（保留 MAC / SMB）
            DeviceInfo merged;
            {
                std::lock_guard<std::mutex> l(g_mapMtx);
                auto it = g_deviceMap.find(rep->ip);
                if (it != g_deviceMap.end()) merged = it->second;
            }
            merged.ip = rep->ip;
            std::wstring name = rep->brand.empty() ? L"" : rep->brand + L" ";
            name += rep->model;
            if (name.empty()) name = L"(未知)";
            merged.hostname = name;
            merged.vendor = rep->brand.empty() ? L"(未知)" : rep->brand;
            merged.deviceType = rep->type;
            if (!rep->osVer.empty()) merged.osName = rep->osVer;
            ListView_SetItemText(g_hListDevices, row, 1, const_cast<LPWSTR>(merged.hostname.c_str()));
            ListView_SetItemText(g_hListDevices, row, 2, const_cast<LPWSTR>(merged.deviceType.c_str()));
            ListView_SetItemText(g_hListDevices, row, 3, const_cast<LPWSTR>(merged.osName.c_str()));
            ListView_SetItemText(g_hListDevices, row, 5, const_cast<LPWSTR>(L"HTTP浏览器"));
            { std::lock_guard<std::mutex> l(g_mapMtx); g_deviceMap[rep->ip] = merged; }
            Log(L"[识别] " + rep->ip + L" => " + merged.hostname + L" | " + merged.deviceType +
                (rep->osVer.empty() ? L"" : L" | " + rep->osVer));
            delete rep;
        }
        break;
    }
    case WM_SCAN_PROGRESS: {
        SetWindowTextW(g_hStaticScanInfo,
            (L"扫描中... ." + std::to_wstring((int)wParam)).c_str());
        break;
    }
    case WM_SCAN_DONE: {
        int c = (int)wParam;
        EnableWindow(g_hBtnScan, TRUE);
        g_scanning = false;
        SetWindowTextW(g_hStaticScanInfo, (L"发现" + std::to_wstring(c) + L"台设备").c_str());
        SetStatus(L"扫描完成");
        break;
    }
    case WM_STATUS_UPDATE: {
        std::wstring* p = (std::wstring*)lParam;
        if (p) { SetStatus(*p); delete p; }
        break;
    }
    case WM_HTTP_UPDATE: {
        std::wstring* p = (std::wstring*)lParam;
        if (p) {
            SetWindowTextW(g_hStaticHttpUrl, p->c_str());
            EnableWindow(g_hBtnOpenUrl, TRUE);
            delete p;
        }
        break;
    }
    case WM_NOTIFY: {
        LPNMHDR pn = (LPNMHDR)lParam;
        if (pn->idFrom == IDC_LIST_DEVICES && pn->code == NM_DBLCLK) {
            int sel = ListView_GetNextItem(g_hListDevices, -1, LVNI_SELECTED);
            if (sel != -1) {
                wchar_t b[256] = { 0 };
                ListView_GetItemText(g_hListDevices, sel, 0, b, 256);
                Log(L"已选中: " + std::wstring(b));
            }
        }
        break;
    }
    case WM_COMMAND: {
        WORD id = LOWORD(wParam);
        switch (id) {
        case IDC_BTN_SCAN: {
            if (g_scanning) break;
            g_scanGen++;                 // 新扫描代次，使旧信息回调失效
            g_scanning = true;
            ListView_DeleteAllItems(g_hListDevices);
            EnableWindow(g_hBtnScan, FALSE);
            SetStatus(L"扫描中...");
            SetWindowTextW(g_hStaticScanInfo, L"扫描中...");
            std::thread(ScanLanThread).detach();
            break;
        }
        case IDC_BTN_SELFILE: {
            std::wstring f;
            if (BrowseForFile(hWnd, f)) {
                g_selectedPath = f; g_httpSharePath = f;
                SetEditText(g_hEditFilePath, f);
                Log(L"已选择文件: " + f);
            }
            break;
        }
        case IDC_BTN_SELDIR: {
            std::wstring d;
            if (BrowseForDir(hWnd, d)) {
                g_selectedPath = d; g_httpSharePath = d;
                SetEditText(g_hEditFilePath, d);
                Log(L"已选择目录: " + d);
            }
            break;
        }
        case IDC_BTN_HTTPSTART: {
            int port = _wtoi(GetEditText(g_hEditHttpPort).c_str());
            if (port <= 0 || port > 65535) {
                MessageBoxW(hWnd, L"端口无效", L"错误", MB_ICONERROR); break;
            }
            if (g_httpRunning) break;
            if (g_httpSharePath.empty()) g_httpSharePath = GetEditText(g_hEditFilePath);
            if (g_httpSharePath.empty()) g_httpSharePath = g_selectedPath;
            if (g_httpRecvDir.empty()) g_httpRecvDir = L"C:\\LanTransfer_Received";
            std::error_code ec;
            fs::create_directories(g_httpRecvDir, ec);
            g_httpRunning = true;
            EnableWindow(g_hBtnHttpStart, FALSE);
            EnableWindow(g_hBtnHttpStop, TRUE);
            SetStatus(L"HTTP服务启动中...");
            Log(L"[HTTP] 上传文件将保存到: " + g_httpRecvDir);
            g_httpThread = std::thread(HttpServerThread, port);
            std::thread(EnsureFirewallRule, port).detach();
            break;
        }
        case IDC_BTN_HTTPSTOP: {
            StopHttpServer();
            SetStatus(L"HTTP服务已停止");
            break;
        }
        case IDC_BTN_OPENURL: {
            wchar_t url[256] = { 0 };
            GetWindowText(g_hStaticHttpUrl, url, 256);
            if (url[0]) ShellExecuteW(nullptr, L"open", url, nullptr, nullptr, SW_SHOWNORMAL);
            break;
        }
        case IDC_BTN_SENDONE: {
            if (g_sending) {
                MessageBoxW(hWnd, L"传输中...", L"提示", MB_ICONINFORMATION); break;
            }
            std::wstring path = GetEditText(g_hEditFilePath);
            if (path.empty()) {
                MessageBoxW(hWnd, L"先选择文件", L"提示", MB_ICONWARNING); break;
            }
            int sel = ListView_GetNextItem(g_hListDevices, -1, LVNI_SELECTED);
            if (sel == -1) {
                MessageBoxW(hWnd, L"先选中设备", L"提示", MB_ICONWARNING); break;
            }
            wchar_t b[256] = { 0 };
            ListView_GetItemText(g_hListDevices, sel, 0, b, 256);
            std::wstring ip = b, share, sub;
            ParseSharePath(GetEditText(g_hEditShare), share, sub);
            g_sending = true;
            SetStatus(L"发送到 " + ip + L"...");
            std::thread(SendToOneThread, ip, path, share, sub,
                GetEditText(g_hEditUser), GetEditText(g_hEditPass)).detach();
            break;
        }
        case IDC_BTN_SENDALL: {
            if (g_sending) {
                MessageBoxW(hWnd, L"传输中...", L"提示", MB_ICONINFORMATION); break;
            }
            std::wstring path = GetEditText(g_hEditFilePath);
            if (path.empty()) {
                MessageBoxW(hWnd, L"先选择文件", L"提示", MB_ICONWARNING); break;
            }
            if (ListView_GetItemCount(g_hListDevices) == 0) {
                MessageBoxW(hWnd, L"无在线设备", L"提示", MB_ICONWARNING); break;
            }
            std::wstring share, sub;
            ParseSharePath(GetEditText(g_hEditShare), share, sub);
            g_sending = true;
            SetStatus(L"发送到所有设备...");
            std::thread(SendToAllThread, path, share, sub,
                GetEditText(g_hEditUser), GetEditText(g_hEditPass)).detach();
            break;
        }
        }
        break;
    }
    case WM_CLOSE: {
        g_scanning = false;
        g_sending = false;
        if (g_httpRunning || g_httpThread.joinable()) {
            g_httpRunning = false;
            StopHttpServer();
        }
        DestroyWindow(hWnd);
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// ============== WinMain ==============
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    g_hInst = hInstance;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxW(nullptr, L"Winsock初始化失败", L"错误", MB_ICONERROR);
        return 1;
    }
    INITCOMMONCONTROLSEX ic = { sizeof(ic), ICC_STANDARD_CLASSES | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&ic);

    BuildOUIMap();

    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"LanTransferWnd";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(0, L"LanTransferWnd", L"局域网文件传输工具 (全设备修复版)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 620, 565, nullptr, nullptr, hInstance, nullptr);
    if (!g_hWnd) { WSACleanup(); return 1; }
    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);
    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    WSACleanup();
    return (int)m.wParam;
}
