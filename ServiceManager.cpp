
#include "ServiceManager.h"

#include <windows.h>
#include <rpc.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <winhttp.h>
#include <wtsapi32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "ServiceRpc.h"

namespace
{
    constexpr wchar_t kServiceName[] = L"AntivirusClient.SessionLauncher";
    constexpr wchar_t kServiceDisplayName[] = L"AntivirusClient Session Launcher";
    constexpr wchar_t kServiceDescription[] = L"Launches AntivirusClient in user sessions.";
    constexpr wchar_t kServiceExecutableName[] = L"AntivirusClient.Service.exe";
    constexpr wchar_t kGuiExecutableName[] = L"AntivirusClient.exe";
    constexpr wchar_t kRpcProtocol[] = L"ncalrpc";
    constexpr wchar_t kRpcEndpoint[] = L"AntivirusClient.Service.Control";
    constexpr wchar_t kHiddenSwitch[] = L"--hidden";

    constexpr DWORD kServicePollIntervalMs = 500;
    constexpr DWORD kServiceStartTimeoutMs = 30000;
    constexpr wchar_t kBackendHost[] = L"localhost";
    constexpr INTERNET_PORT kBackendPort = 8443;

    struct HttpResponse
    {
        DWORD statusCode = 0;
        std::string body;
    };

    struct AuthCache
    {
        bool authenticated = false;
        std::wstring login;
        std::string accessToken;
        std::string refreshToken;
        std::string deviceId;
        ULONGLONG nextRefreshTick = 0;
    };

    struct LicenseCache
    {
        bool hasLicense = false;
        bool blocked = false;
        std::wstring expiresAt;
        std::wstring productName;
        std::string activationCode;
        uint64_t lifetimeSec = 0;
        ULONGLONG nextRefreshTick = 0;
    };

    std::wstring GetModulePath()
    {
        std::wstring path(MAX_PATH, L'\0');
        while (true)
        {
            DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
            if (length == 0)
            {
                return {};
            }

            if (length < path.size() - 1)
            {
                path.resize(length);
                return path;
            }

            path.resize(path.size() * 2);
        }
    }

    std::wstring GetDirectoryPath(std::wstring const& path)
    {
        size_t const separator = path.find_last_of(L"\\/");
        if (separator == std::wstring::npos)
        {
            return {};
        }

        return path.substr(0, separator + 1);
    }

    std::wstring BuildSiblingPath(std::wstring const& executablePath, std::wstring_view fileName)
    {
        std::wstring directory = GetDirectoryPath(executablePath);
        if (directory.empty())
        {
            return {};
        }

        directory.append(fileName);
        return directory;
    }

    std::wstring BuildServiceBinaryPath(std::wstring const& guiExecutablePath)
    {
        std::wstring servicePath = BuildSiblingPath(guiExecutablePath, kServiceExecutableName);
        if (servicePath.empty())
        {
            return {};
        }

        std::wstring quoted = L"\"";
        quoted.append(servicePath);
        quoted.push_back(L'\"');
        return quoted;
    }

    SC_HANDLE OpenServiceWithAccess(SC_HANDLE scm, DWORD accessMask)
    {
        return OpenServiceW(scm, kServiceName, accessMask);
    }

    bool QueryServiceStatusProcess(SC_HANDLE serviceHandle, SERVICE_STATUS_PROCESS& status)
    {
        DWORD bytesNeeded = 0;
        return QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded) != FALSE;
    }

    bool WaitForServiceRunning(SC_HANDLE serviceHandle, DWORD timeoutMs)
    {
        ULONGLONG const deadline = GetTickCount64() + timeoutMs;
        SERVICE_STATUS_PROCESS status{};
        while (GetTickCount64() <= deadline)
        {
            if (!QueryServiceStatusProcess(serviceHandle, status))
            {
                return false;
            }

            if (status.dwCurrentState == SERVICE_RUNNING)
            {
                return true;
            }

            if (status.dwCurrentState == SERVICE_STOPPED)
            {
                return false;
            }

            Sleep(kServicePollIntervalMs);
        }

        return false;
    }

    bool EnsureServiceRunning(SC_HANDLE serviceHandle, bool& startedByCaller)
    {
        startedByCaller = false;

        SERVICE_STATUS_PROCESS status{};
        if (!QueryServiceStatusProcess(serviceHandle, status))
        {
            return false;
        }

        if (status.dwCurrentState == SERVICE_RUNNING)
        {
            return true;
        }

        if (status.dwCurrentState == SERVICE_START_PENDING)
        {
            return WaitForServiceRunning(serviceHandle, kServiceStartTimeoutMs);
        }

        if (!StartServiceW(serviceHandle, 0, nullptr))
        {
            if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
            {
                return false;
            }
        }
        else
        {
            startedByCaller = true;
        }

        return WaitForServiceRunning(serviceHandle, kServiceStartTimeoutMs);
    }

    void EnsureServiceConfiguration(SC_HANDLE serviceHandle, std::wstring const& binaryPath)
    {
        ChangeServiceConfigW(
            serviceHandle,
            SERVICE_NO_CHANGE,
            SERVICE_AUTO_START,
            SERVICE_NO_CHANGE,
            binaryPath.empty() ? nullptr : binaryPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        SERVICE_DESCRIPTIONW description{};
        description.lpDescription = const_cast<LPWSTR>(kServiceDescription);
        ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_DESCRIPTION, &description);
    }

    SC_HANDLE CreateServiceIfMissing(SC_HANDLE scm)
    {
        std::wstring executablePath = GetModulePath();
        if (executablePath.empty())
        {
            return nullptr;
        }

        std::wstring binaryPath = BuildServiceBinaryPath(executablePath);
        if (binaryPath.empty())
        {
            return nullptr;
        }

        SC_HANDLE serviceHandle = OpenServiceWithAccess(scm, SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG);
        if (serviceHandle != nullptr)
        {
            EnsureServiceConfiguration(serviceHandle, binaryPath);
            return serviceHandle;
        }

        if (GetLastError() != ERROR_SERVICE_DOES_NOT_EXIST)
        {
            return nullptr;
        }

        serviceHandle = CreateServiceW(
            scm,
            kServiceName,
            kServiceDisplayName,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binaryPath.c_str(),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (serviceHandle == nullptr)
        {
            return nullptr;
        }

        EnsureServiceConfiguration(serviceHandle, binaryPath);
        return serviceHandle;
    }

    std::string WideToUtf8(std::wstring const& value)
    {
        if (value.empty())
        {
            return {};
        }

        int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (required <= 1)
        {
            return {};
        }

        std::string result(static_cast<size_t>(required - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), required, nullptr, nullptr);
        return result;
    }

    std::wstring Utf8ToWide(std::string const& value)
    {
        if (value.empty())
        {
            return {};
        }

        int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
        if (required <= 1)
        {
            return {};
        }

        std::wstring result(static_cast<size_t>(required - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), required);
        return result;
    }

    std::string JsonEscape(std::string_view value)
    {
        std::string result;
        result.reserve(value.size() + 8);
        for (char c : value)
        {
            if (c == '\\')
            {
                result += "\\\\";
            }
            else if (c == '"')
            {
                result += "\\\"";
            }
            else if (c == '\n')
            {
                result += "\\n";
            }
            else if (c == '\r')
            {
                result += "\\r";
            }
            else
            {
                result.push_back(c);
            }
        }
        return result;
    }
    size_t SkipWs(std::string const& s, size_t i)
    {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n'))
        {
            ++i;
        }
        return i;
    }

    bool ExtractJsonRaw(std::string const& json, std::string const& key, std::string& out)
    {
        std::string needle = "\"" + key + "\"";
        size_t pos = json.find(needle);
        if (pos == std::string::npos)
        {
            return false;
        }

        pos = json.find(':', pos + needle.size());
        if (pos == std::string::npos)
        {
            return false;
        }

        pos = SkipWs(json, pos + 1);
        if (pos >= json.size())
        {
            return false;
        }

        if (json[pos] == '"')
        {
            std::string value;
            for (size_t i = pos + 1; i < json.size(); ++i)
            {
                char c = json[i];
                if (c == '\\' && i + 1 < json.size())
                {
                    value.push_back(json[++i]);
                    continue;
                }
                if (c == '"')
                {
                    out = std::move(value);
                    return true;
                }
                value.push_back(c);
            }
            return false;
        }

        size_t end = pos;
        while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ']')
        {
            ++end;
        }
        out = json.substr(pos, end - pos);
        return true;
    }

    bool ExtractJsonString(std::string const& json, std::string const& key, std::string& out)
    {
        return ExtractJsonRaw(json, key, out);
    }

    bool ExtractJsonUInt64(std::string const& json, std::string const& key, uint64_t& out)
    {
        std::string raw;
        if (!ExtractJsonRaw(json, key, raw))
        {
            return false;
        }

        raw.erase(std::remove_if(raw.begin(), raw.end(), [](char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }), raw.end());

        if (raw.empty())
        {
            return false;
        }

        char* end = nullptr;
        unsigned long long parsed = strtoull(raw.c_str(), &end, 10);
        if (end == raw.c_str() || *end != '\0')
        {
            return false;
        }

        out = static_cast<uint64_t>(parsed);
        return true;
    }

    bool ExtractJsonBool(std::string const& json, std::string const& key, bool& out)
    {
        std::string raw;
        if (!ExtractJsonRaw(json, key, raw))
        {
            return false;
        }

        raw.erase(std::remove_if(raw.begin(), raw.end(), [](char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        }), raw.end());

        if (raw == "true")
        {
            out = true;
            return true;
        }
        if (raw == "false")
        {
            out = false;
            return true;
        }

        return false;
    }

    uint64_t GetUnixTimeNow()
    {
        auto now = std::chrono::system_clock::now();
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
        return static_cast<uint64_t>(sec.count());
    }

    ULONGLONG SecondsToTickDelta(uint64_t sec)
    {
        if (sec > (static_cast<uint64_t>(MAXDWORD) / 1000ULL))
        {
            return static_cast<ULONGLONG>(MAXDWORD);
        }
        return sec * 1000ULL;
    }

    std::wstring BuildDeviceId()
    {
        wchar_t machine[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD size = _countof(machine);
        if (!GetComputerNameW(machine, &size))
        {
            wcscpy_s(machine, L"UnknownMachine");
        }

        std::wstring id = machine;
        id += L"-default";
        return id;
    }

    std::optional<HttpResponse> SendHttpsRequest(
        std::wstring const& method,
        std::wstring const& path,
        std::string const& bodyUtf8,
        std::string const& bearerToken)
    {
        HINTERNET session = WinHttpOpen(L"AntivirusClientService/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (session == nullptr)
        {
            return std::nullopt;
        }

        HINTERNET connection = WinHttpConnect(session, kBackendHost, kBackendPort, 0);
        if (connection == nullptr)
        {
            WinHttpCloseHandle(session);
            return std::nullopt;
        }

        HINTERNET request = WinHttpOpenRequest(connection, method.c_str(), path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (request == nullptr)
        {
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return std::nullopt;
        }

        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));

        std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
        if (!bearerToken.empty())
        {
            headers += L"Authorization: Bearer ";
            headers += Utf8ToWide(bearerToken);
            headers += L"\r\n";
        }

        BOOL ok = WinHttpSendRequest(
            request,
            headers.c_str(),
            static_cast<DWORD>(headers.size()),
            bodyUtf8.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(bodyUtf8.data()),
            static_cast<DWORD>(bodyUtf8.size()),
            static_cast<DWORD>(bodyUtf8.size()),
            0);

        if (!ok)
        {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return std::nullopt;
        }

        if (!WinHttpReceiveResponse(request, nullptr))
        {
            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
            return std::nullopt;
        }

        HttpResponse response{};
        DWORD statusSize = sizeof(response.statusCode);
        WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &response.statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);

        for (;;)
        {
            DWORD available = 0;
            if (!WinHttpQueryDataAvailable(request, &available) || available == 0)
            {
                break;
            }

            size_t offset = response.body.size();
            response.body.resize(offset + available);
            DWORD read = 0;
            if (!WinHttpReadData(request, response.body.data() + offset, available, &read))
            {
                response.body.resize(offset);
                break;
            }

            response.body.resize(offset + read);
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return response;
    }

    AntivirusService::RpcResult MapHttpToRpc(DWORD status)
    {
        if (status == 400)
        {
            return AntivirusService::RpcResult::InvalidArgument;
        }
        if (status == 401 || status == 403)
        {
            return AntivirusService::RpcResult::Unauthorized;
        }
        if (status == 404)
        {
            return AntivirusService::RpcResult::NoLicense;
        }
        if (status == 409)
        {
            return AntivirusService::RpcResult::Conflict;
        }
        if (status >= 500)
        {
            return AntivirusService::RpcResult::ServiceUnavailable;
        }
        return AntivirusService::RpcResult::Error;
    }

    AntivirusRpcStatus ToRpcStatus(AntivirusService::RpcResult result)
    {
        return static_cast<AntivirusRpcStatus>(result);
    }

    AntivirusService::RpcResult FromRpcStatus(AntivirusRpcStatus status)
    {
        return static_cast<AntivirusService::RpcResult>(status);
    }

    bool WriteRpcString(wchar_t* target, size_t count, std::wstring const& value)
    {
        if (target == nullptr || count == 0)
        {
            return false;
        }
        return wcsncpy_s(target, count, value.c_str(), _TRUNCATE) == 0;
    }

    bool StartServiceElevated()
    {
        SHELLEXECUTEINFOW executeInfo{};
        executeInfo.cbSize = sizeof(executeInfo);
        executeInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        executeInfo.hwnd = nullptr;
        executeInfo.lpVerb = L"runas";
        executeInfo.lpFile = L"powershell.exe";
        executeInfo.lpParameters = L"-NoProfile -ExecutionPolicy Bypass -Command \"Start-Service -Name 'AntivirusClient.SessionLauncher'\"";
        executeInfo.lpDirectory = nullptr;
        executeInfo.nShow = SW_HIDE;

        if (!ShellExecuteExW(&executeInfo))
        {
            return false;
        }

        if (executeInfo.hProcess != nullptr)
        {
            WaitForSingleObject(executeInfo.hProcess, 60000);
            DWORD exitCode = 1;
            GetExitCodeProcess(executeInfo.hProcess, &exitCode);
            CloseHandle(executeInfo.hProcess);
            return exitCode == 0;
        }

        return false;
    }
}

#if defined(ANTIVIRUS_SERVICE_HOST)
namespace
{
    SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
    SERVICE_STATUS g_serviceStatus{};
    DWORD g_checkPoint = 1;
    DWORD g_serviceProcessId = 0;
    bool g_rpcStopRequested = false;
    std::atomic<bool> g_serviceStopping{ false };
    HANDLE g_sessionMonitorStopEvent = nullptr;
    HANDLE g_sessionMonitorThread = nullptr;

    HANDLE g_bgEvent = nullptr;
    HANDLE g_bgThread = nullptr;

    std::mutex g_launchedMutex;
    std::unordered_map<DWORD, DWORD> g_launchedGuiProcessBySession;

    std::mutex g_stateMutex;
    AuthCache g_auth;
    LicenseCache g_license;

    void ClearStateLocked()
    {
        g_auth = {};
        g_license = {};
    }

    bool ParseAuthResponse(std::string const& body, std::wstring& loginOut, std::string& accessOut, std::string& refreshOut)
    {
        std::string login;
        if (!ExtractJsonString(body, "email", login))
        {
            return false;
        }
        if (!ExtractJsonString(body, "accessToken", accessOut))
        {
            return false;
        }
        if (!ExtractJsonString(body, "refreshToken", refreshOut))
        {
            return false;
        }

        loginOut = Utf8ToWide(login);
        return !loginOut.empty() && !accessOut.empty() && !refreshOut.empty();
    }

    bool ParseTicket(std::string const& body, LicenseCache& ticket)
    {
        std::string expires;
        std::string product;
        bool blocked = false;
        uint64_t lifetime = 0;

        if (!ExtractJsonString(body, "expiresAt", expires))
        {
            return false;
        }
        if (!ExtractJsonString(body, "productName", product))
        {
            return false;
        }
        ExtractJsonBool(body, "blocked", blocked);
        if (!ExtractJsonUInt64(body, "ticketLifetimeSeconds", lifetime))
        {
            lifetime = 300;
        }

        ticket.hasLicense = true;
        ticket.blocked = blocked;
        ticket.expiresAt = Utf8ToWide(expires);
        ticket.productName = Utf8ToWide(product);
        ticket.lifetimeSec = lifetime;
        uint64_t refreshSec = std::max<uint64_t>(30, lifetime / 2);
        ticket.nextRefreshTick = GetTickCount64() + SecondsToTickDelta(refreshSec);
        return true;
    }

    AntivirusService::RpcResult LoginInternal(std::wstring const& login, std::wstring const& password, std::wstring& outLogin)
    {
        std::wstring device = BuildDeviceId();
        std::string body = "{\"email\":\"" + JsonEscape(WideToUtf8(login)) +
            "\",\"password\":\"" + JsonEscape(WideToUtf8(password)) +
            "\",\"deviceId\":\"" + JsonEscape(WideToUtf8(device)) + "\"}";

        auto response = SendHttpsRequest(L"POST", L"/auth/login", body, {});
        if (!response.has_value())
        {
            return AntivirusService::RpcResult::Network;
        }
        if (response->statusCode != 200)
        {
            return MapHttpToRpc(response->statusCode);
        }

        std::wstring loginParsed;
        std::string access;
        std::string refresh;
        if (!ParseAuthResponse(response->body, loginParsed, access, refresh))
        {
            return AntivirusService::RpcResult::Error;
        }

        std::lock_guard lock(g_stateMutex);
        g_auth.authenticated = true;
        g_auth.login = loginParsed;
        g_auth.accessToken = std::move(access);
        g_auth.refreshToken = std::move(refresh);
        g_auth.deviceId = WideToUtf8(device);
        g_auth.nextRefreshTick = GetTickCount64() + SecondsToTickDelta(10 * 60);
        g_license = {};
        outLogin = g_auth.login;

        if (g_bgEvent != nullptr)
        {
            SetEvent(g_bgEvent);
        }
        return AntivirusService::RpcResult::Ok;
    }

    AntivirusService::RpcResult RefreshTokenInternal()
    {
        std::wstring login;
        std::string refresh;
        {
            std::lock_guard lock(g_stateMutex);
            if (!g_auth.authenticated || g_auth.refreshToken.empty())
            {
                return AntivirusService::RpcResult::Unauthorized;
            }
            login = g_auth.login;
            refresh = g_auth.refreshToken;
        }

        std::string body = "{\"email\":\"" + JsonEscape(WideToUtf8(login)) +
            "\",\"accessToken\":\"\",\"refreshToken\":\"" + JsonEscape(refresh) + "\"}";

        auto response = SendHttpsRequest(L"POST", L"/auth/refresh", body, {});
        if (!response.has_value())
        {
            return AntivirusService::RpcResult::Network;
        }
        if (response->statusCode != 200)
        {
            AntivirusService::RpcResult mapped = MapHttpToRpc(response->statusCode);
            if (mapped == AntivirusService::RpcResult::Unauthorized)
            {
                std::lock_guard lock(g_stateMutex);
                ClearStateLocked();
            }
            return mapped;
        }

        std::wstring loginParsed;
        std::string access;
        std::string refreshNew;
        if (!ParseAuthResponse(response->body, loginParsed, access, refreshNew))
        {
            return AntivirusService::RpcResult::Error;
        }

        std::lock_guard lock(g_stateMutex);
        g_auth.authenticated = true;
        g_auth.login = loginParsed;
        g_auth.accessToken = std::move(access);
        g_auth.refreshToken = std::move(refreshNew);
        g_auth.nextRefreshTick = GetTickCount64() + SecondsToTickDelta(10 * 60);
        return AntivirusService::RpcResult::Ok;
    }

    AntivirusService::RpcResult VerifyLicenseInternal(LicenseCache& out)
    {
        std::string token;
        std::string activation;
        std::string device;

        {
            std::lock_guard lock(g_stateMutex);
            if (!g_auth.authenticated)
            {
                return AntivirusService::RpcResult::Unauthorized;
            }
            if (g_license.activationCode.empty())
            {
                return AntivirusService::RpcResult::NoLicense;
            }

            token = g_auth.accessToken;
            activation = g_license.activationCode;
            device = g_auth.deviceId;
        }

        std::wstring path = L"/licenses/verify?code=" + Utf8ToWide(activation) + L"&deviceId=" + Utf8ToWide(device);
        auto response = SendHttpsRequest(L"GET", path, {}, token);
        if (!response.has_value())
        {
            return AntivirusService::RpcResult::Network;
        }
        if (response->statusCode != 200)
        {
            return MapHttpToRpc(response->statusCode);
        }

        LicenseCache parsed{};
        parsed.activationCode = activation;
        if (!ParseTicket(response->body, parsed))
        {
            return AntivirusService::RpcResult::Error;
        }

        out = std::move(parsed);
        return AntivirusService::RpcResult::Ok;
    }

    AntivirusService::RpcResult ActivateInternal(std::wstring const& activationCode, AntivirusService::LicenseState& state)
    {
        std::string token;
        std::wstring login;
        std::string device;
        {
            std::lock_guard lock(g_stateMutex);
            if (!g_auth.authenticated)
            {
                return AntivirusService::RpcResult::Unauthorized;
            }
            token = g_auth.accessToken;
            login = g_auth.login;
            device = g_auth.deviceId;
        }

        std::string code = WideToUtf8(activationCode);
        std::string body = "{\"activationKey\":\"" + JsonEscape(code) +
            "\",\"deviceIdentifier\":\"" + JsonEscape(device) +
            "\",\"deviceName\":\"" + JsonEscape(WideToUtf8(login)) + "\"}";

        auto response = SendHttpsRequest(L"POST", L"/licenses/activate", body, token);
        if (!response.has_value())
        {
            return AntivirusService::RpcResult::Network;
        }
        if (response->statusCode != 200)
        {
            return MapHttpToRpc(response->statusCode);
        }

        LicenseCache ticket{};
        ticket.activationCode = code;
        if (!ParseTicket(response->body, ticket))
        {
            // fallback: activation endpoint may not return full ticket
            std::lock_guard lock(g_stateMutex);
            g_license.activationCode = code;
            g_license.hasLicense = false;
            g_license.nextRefreshTick = GetTickCount64() + SecondsToTickDelta(15);
            return AntivirusService::RpcResult::NoLicense;
        }

        std::lock_guard lock(g_stateMutex);
        g_license = ticket;

        state.hasLicense = g_license.hasLicense;
        state.blocked = g_license.blocked;
        state.expiresAt = g_license.expiresAt;
        state.productName = g_license.productName;
        return AntivirusService::RpcResult::Ok;
    }

    DWORD WINAPI BgThreadProc([[maybe_unused]] LPVOID)
    {
        while (!g_serviceStopping.load())
        {
            ULONGLONG now = GetTickCount64();

            bool refreshToken = false;
            bool refreshLicense = false;
            {
                std::lock_guard lock(g_stateMutex);
                refreshToken = g_auth.authenticated && g_auth.nextRefreshTick != 0 && now >= g_auth.nextRefreshTick;
                refreshLicense = g_auth.authenticated && !g_license.activationCode.empty() && g_license.nextRefreshTick != 0 && now >= g_license.nextRefreshTick;
            }

            if (refreshToken)
            {
                AntivirusService::RpcResult rt = RefreshTokenInternal();
                if (rt != AntivirusService::RpcResult::Ok)
                {
                    std::lock_guard lock(g_stateMutex);
                    g_auth.nextRefreshTick = GetTickCount64() + SecondsToTickDelta(30);
                }
            }

            if (refreshLicense)
            {
                LicenseCache refreshed{};
                AntivirusService::RpcResult rl = VerifyLicenseInternal(refreshed);
                std::lock_guard lock(g_stateMutex);
                if (rl == AntivirusService::RpcResult::Ok)
                {
                    std::string code = g_license.activationCode;
                    g_license = refreshed;
                    g_license.activationCode = code;
                }
                else
                {
                    g_license.hasLicense = false;
                    g_license.nextRefreshTick = GetTickCount64() + SecondsToTickDelta(30);
                    if (rl == AntivirusService::RpcResult::Unauthorized)
                    {
                        ClearStateLocked();
                    }
                }
            }

            if (g_bgEvent == nullptr)
            {
                Sleep(2000);
                continue;
            }

            DWORD wr = WaitForSingleObject(g_bgEvent, 2000);
            if (wr == WAIT_OBJECT_0)
            {
                if (g_serviceStopping.load())
                {
                    break;
                }
                ResetEvent(g_bgEvent);
            }
        }

        return 0;
    }

    void TrackLaunchedGuiProcess(DWORD sessionId, DWORD processId)
    {
        std::lock_guard lock(g_launchedMutex);
        g_launchedGuiProcessBySession[sessionId] = processId;
    }

    bool IsProcessRunning(DWORD processId)
    {
        HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, processId);
        if (process == nullptr)
        {
            return false;
        }

        DWORD waitResult = WaitForSingleObject(process, 0);
        CloseHandle(process);
        return waitResult == WAIT_TIMEOUT;
    }

    bool IsSessionGuiAlreadyRunning(DWORD sessionId)
    {
        std::lock_guard lock(g_launchedMutex);
        auto it = g_launchedGuiProcessBySession.find(sessionId);
        if (it == g_launchedGuiProcessBySession.end())
        {
            return false;
        }

        if (IsProcessRunning(it->second))
        {
            return true;
        }

        g_launchedGuiProcessBySession.erase(it);
        return false;
    }

    void UpdateServiceStatus(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHint = 0)
    {
        if (g_statusHandle == nullptr)
        {
            return;
        }

        g_serviceStatus.dwCurrentState = state;
        g_serviceStatus.dwWin32ExitCode = win32ExitCode;
        g_serviceStatus.dwWaitHint = waitHint;
        g_serviceStatus.dwControlsAccepted = 0;

        if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
        {
            g_serviceStatus.dwCheckPoint = g_checkPoint++;
        }
        else
        {
            g_serviceStatus.dwCheckPoint = 0;
        }

        if (state == SERVICE_RUNNING)
        {
            g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;
        }

        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }

    HANDLE WaitForUserToken(DWORD sessionId)
    {
        for (int attempt = 0; attempt < 120; ++attempt)
        {
            HANDLE token = nullptr;
            if (WTSQueryUserToken(sessionId, &token))
            {
                return token;
            }

            if (g_serviceStopping.load())
            {
                return nullptr;
            }

            Sleep(500);
        }

        return nullptr;
    }

    bool LaunchGuiHiddenInSession(DWORD sessionId)
    {
        if (g_serviceStopping.load())
        {
            return false;
        }

        if (sessionId == 0 || IsSessionGuiAlreadyRunning(sessionId))
        {
            return true;
        }

        HANDLE impersonationToken = WaitForUserToken(sessionId);
        if (impersonationToken == nullptr)
        {
            return false;
        }

        HANDLE primaryToken = nullptr;
        bool duplicated = DuplicateTokenEx(
            impersonationToken,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primaryToken) != FALSE;

        CloseHandle(impersonationToken);
        if (!duplicated)
        {
            return false;
        }

        LPVOID environment = nullptr;
        if (!CreateEnvironmentBlock(&environment, primaryToken, FALSE))
        {
            environment = nullptr;
        }

        std::wstring servicePath = GetModulePath();
        std::wstring appPath = BuildSiblingPath(servicePath, kGuiExecutableName);
        if (appPath.empty())
        {
            if (environment != nullptr)
            {
                DestroyEnvironmentBlock(environment);
            }
            CloseHandle(primaryToken);
            return false;
        }

        std::wstring commandLine = L"\"";
        commandLine.append(appPath);
        commandLine.append(L"\" ");
        commandLine.append(kHiddenSwitch);

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION processInfo{};
        DWORD creationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP;

        bool started = CreateProcessAsUserW(
            primaryToken,
            appPath.c_str(),
            commandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            creationFlags,
            environment,
            nullptr,
            &startupInfo,
            &processInfo) != FALSE;

        if (environment != nullptr)
        {
            DestroyEnvironmentBlock(environment);
        }

        CloseHandle(primaryToken);
        if (!started)
        {
            return false;
        }

        TrackLaunchedGuiProcess(sessionId, processInfo.dwProcessId);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return true;
    }

    void LaunchGuiInAllActiveSessions()
    {
        PWTS_SESSION_INFOW sessions = nullptr;
        DWORD sessionCount = 0;

        if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &sessionCount))
        {
            return;
        }

        for (DWORD index = 0; index < sessionCount; ++index)
        {
            auto const& session = sessions[index];
            if (session.SessionId == 0)
            {
                continue;
            }

            if (session.State == WTSActive || session.State == WTSConnected)
            {
                LaunchGuiHiddenInSession(session.SessionId);
            }
        }

        WTSFreeMemory(sessions);
    }

    DWORD WINAPI SessionMonitorThreadProc([[maybe_unused]] LPVOID)
    {
        while (!g_serviceStopping.load())
        {
            LaunchGuiInAllActiveSessions();
            if (g_sessionMonitorStopEvent == nullptr)
            {
                Sleep(5000);
                continue;
            }
            DWORD wr = WaitForSingleObject(g_sessionMonitorStopEvent, 5000);
            if (wr == WAIT_OBJECT_0)
            {
                break;
            }
        }
        return 0;
    }

    RPC_STATUS StartRpcServer()
    {
        RPC_STATUS status = RpcServerUseProtseqEpW(
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
            RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
            reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
            nullptr);

        if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT)
        {
            return status;
        }

        status = RpcServerRegisterIf2(
            AntivirusServiceControl_v1_0_s_ifspec,
            nullptr,
            nullptr,
            RPC_IF_ALLOW_LOCAL_ONLY,
            RPC_C_LISTEN_MAX_CALLS_DEFAULT,
            static_cast<unsigned int>(-1),
            nullptr);

        if (status != RPC_S_OK && status != RPC_S_TYPE_ALREADY_REGISTERED)
        {
            return status;
        }

        return RPC_S_OK;
    }

    RPC_STATUS RunRpcServerLoop()
    {
        RPC_STATUS status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
        if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING)
        {
            return status;
        }

        status = RpcMgmtWaitServerListen();
        if (status == RPC_S_OK || status == RPC_S_NOT_LISTENING)
        {
            return RPC_S_OK;
        }

        return status;
    }

    DWORD WINAPI ServiceControlHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, [[maybe_unused]] LPVOID)
    {
        switch (controlCode)
        {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            return NO_ERROR;
        case SERVICE_CONTROL_SESSIONCHANGE:
            if (eventData != nullptr)
            {
                auto const* notification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
                if (notification->dwSessionId != 0 &&
                    (eventType == WTS_SESSION_LOGON ||
                        eventType == WTS_SESSION_UNLOCK ||
                        eventType == WTS_CONSOLE_CONNECT ||
                        eventType == WTS_REMOTE_CONNECT))
                {
                    LaunchGuiHiddenInSession(notification->dwSessionId);
                }
            }
            return NO_ERROR;
        default:
            return NO_ERROR;
        }
    }

    void WINAPI ServiceMain([[maybe_unused]] DWORD, [[maybe_unused]] LPWSTR*)
    {
        g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandler, nullptr);
        if (g_statusHandle == nullptr)
        {
            return;
        }

        g_serviceStatus = {};
        g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        g_serviceStatus.dwServiceSpecificExitCode = 0;
        g_checkPoint = 1;
        g_serviceProcessId = GetCurrentProcessId();
        g_rpcStopRequested = false;
        g_serviceStopping = false;

        g_sessionMonitorStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        g_bgEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 5000);

        RPC_STATUS rpcStatus = StartRpcServer();
        if (rpcStatus != RPC_S_OK)
        {
            g_serviceStopping = true;
            UpdateServiceStatus(SERVICE_STOPPED, rpcStatus, 0);
            return;
        }

        g_sessionMonitorThread = CreateThread(nullptr, 0, &SessionMonitorThreadProc, nullptr, 0, nullptr);
        g_bgThread = CreateThread(nullptr, 0, &BgThreadProc, nullptr, 0, nullptr);

        LaunchGuiInAllActiveSessions();
        UpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

        rpcStatus = RunRpcServerLoop();

        g_serviceStopping = true;
        UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);

        if (g_sessionMonitorStopEvent != nullptr)
        {
            SetEvent(g_sessionMonitorStopEvent);
        }
        if (g_bgEvent != nullptr)
        {
            SetEvent(g_bgEvent);
        }

        if (g_sessionMonitorThread != nullptr)
        {
            WaitForSingleObject(g_sessionMonitorThread, 10000);
            CloseHandle(g_sessionMonitorThread);
            g_sessionMonitorThread = nullptr;
        }
        if (g_bgThread != nullptr)
        {
            WaitForSingleObject(g_bgThread, 10000);
            CloseHandle(g_bgThread);
            g_bgThread = nullptr;
        }

        if (g_sessionMonitorStopEvent != nullptr)
        {
            CloseHandle(g_sessionMonitorStopEvent);
            g_sessionMonitorStopEvent = nullptr;
        }
        if (g_bgEvent != nullptr)
        {
            CloseHandle(g_bgEvent);
            g_bgEvent = nullptr;
        }

        RpcServerUnregisterIf(AntivirusServiceControl_v1_0_s_ifspec, nullptr, FALSE);

        DWORD exitCode = (rpcStatus == RPC_S_OK || g_rpcStopRequested) ? NO_ERROR : rpcStatus;
        UpdateServiceStatus(SERVICE_STOPPED, exitCode, 0);
    }
}

extern "C" void RpcStopService([[maybe_unused]] handle_t)
{
    g_rpcStopRequested = true;
    RpcMgmtStopServerListening(nullptr);
}

extern "C" AntivirusRpcStatus RpcGetCurrentUser([[maybe_unused]] handle_t, RpcUserInfo* user)
{
    if (user == nullptr)
    {
        return ToRpcStatus(AntivirusService::RpcResult::InvalidArgument);
    }

    user->authenticated = 0;
    user->login[0] = L'\0';

    std::lock_guard lock(g_stateMutex);
    user->authenticated = g_auth.authenticated ? 1 : 0;
    if (g_auth.authenticated)
    {
        WriteRpcString(user->login, _countof(user->login), g_auth.login);
    }

    return ToRpcStatus(AntivirusService::RpcResult::Ok);
}

extern "C" AntivirusRpcStatus RpcLogin([[maybe_unused]] handle_t, const wchar_t* login, const wchar_t* password, RpcUserInfo* user)
{
    if (login == nullptr || password == nullptr || user == nullptr)
    {
        return ToRpcStatus(AntivirusService::RpcResult::InvalidArgument);
    }

    std::wstring loginOut;
    AntivirusService::RpcResult result = LoginInternal(login, password, loginOut);

    user->authenticated = (result == AntivirusService::RpcResult::Ok) ? 1 : 0;
    user->login[0] = L'\0';
    if (result == AntivirusService::RpcResult::Ok)
    {
        WriteRpcString(user->login, _countof(user->login), loginOut);
    }

    return ToRpcStatus(result);
}

extern "C" AntivirusRpcStatus RpcLogout([[maybe_unused]] handle_t)
{
    std::lock_guard lock(g_stateMutex);
    ClearStateLocked();
    return ToRpcStatus(AntivirusService::RpcResult::Ok);
}

extern "C" AntivirusRpcStatus RpcGetLicense([[maybe_unused]] handle_t, RpcLicenseInfo* license)
{
    if (license == nullptr)
    {
        return ToRpcStatus(AntivirusService::RpcResult::InvalidArgument);
    }

    AntivirusService::LicenseState state{};
    AntivirusService::RpcResult result = AntivirusService::RpcResult::NoLicense;

    {
        std::lock_guard lock(g_stateMutex);
        if (!g_auth.authenticated)
        {
            result = AntivirusService::RpcResult::Unauthorized;
        }
        else if (g_license.hasLicense)
        {
            state.hasLicense = true;
            state.blocked = g_license.blocked;
            state.expiresAt = g_license.expiresAt;
            state.productName = g_license.productName;
            result = AntivirusService::RpcResult::Ok;
        }
        else if (g_license.activationCode.empty())
        {
            result = AntivirusService::RpcResult::NoLicense;
        }
    }

    if (result == AntivirusService::RpcResult::NoLicense)
    {
        LicenseCache refreshed{};
        AntivirusService::RpcResult verifyResult = VerifyLicenseInternal(refreshed);
        if (verifyResult == AntivirusService::RpcResult::Ok)
        {
            std::lock_guard lock(g_stateMutex);
            g_license = refreshed;
            state.hasLicense = true;
            state.blocked = g_license.blocked;
            state.expiresAt = g_license.expiresAt;
            state.productName = g_license.productName;
            result = AntivirusService::RpcResult::Ok;
        }
        else
        {
            result = verifyResult;
        }
    }

    license->hasLicense = (result == AntivirusService::RpcResult::Ok && state.hasLicense) ? 1 : 0;
    license->blocked = state.blocked ? 1 : 0;
    license->expiresAt[0] = L'\0';
    license->productName[0] = L'\0';

    if (result == AntivirusService::RpcResult::Ok)
    {
        WriteRpcString(license->expiresAt, _countof(license->expiresAt), state.expiresAt);
        WriteRpcString(license->productName, _countof(license->productName), state.productName);
    }

    return ToRpcStatus(result);
}

extern "C" AntivirusRpcStatus RpcActivate([[maybe_unused]] handle_t, const wchar_t* code, RpcLicenseInfo* license)
{
    if (code == nullptr || license == nullptr)
    {
        return ToRpcStatus(AntivirusService::RpcResult::InvalidArgument);
    }

    AntivirusService::LicenseState state{};
    AntivirusService::RpcResult result = ActivateInternal(code, state);

    license->hasLicense = (result == AntivirusService::RpcResult::Ok && state.hasLicense) ? 1 : 0;
    license->blocked = state.blocked ? 1 : 0;
    license->expiresAt[0] = L'\0';
    license->productName[0] = L'\0';
    if (result == AntivirusService::RpcResult::Ok)
    {
        WriteRpcString(license->expiresAt, _countof(license->expiresAt), state.expiresAt);
        WriteRpcString(license->productName, _countof(license->productName), state.productName);
    }

    return ToRpcStatus(result);
}

extern "C" AntivirusRpcStatus RpcGetAntivirusState([[maybe_unused]] handle_t, int* enabled)
{
    if (enabled == nullptr)
    {
        return ToRpcStatus(AntivirusService::RpcResult::InvalidArgument);
    }

    RpcLicenseInfo license{};
    AntivirusRpcStatus status = RpcGetLicense(nullptr, &license);
    if (status != RpcStatusOk)
    {
        *enabled = 0;
        return status;
    }

    *enabled = (license.hasLicense != 0 && license.blocked == 0) ? 1 : 0;
    return RpcStatusOk;
}

namespace AntivirusService
{
    int RunServiceMode()
    {
        SERVICE_TABLE_ENTRYW table[] =
        {
            { const_cast<LPWSTR>(kServiceName), &ServiceMain },
            { nullptr, nullptr }
        };
        if (!StartServiceCtrlDispatcherW(table))
        {
            return static_cast<int>(GetLastError());
        }
        return 0;
    }

    GuiStartupDecision PrepareGuiStartup() { return GuiStartupDecision::Error; }
    bool RequestServiceStop() { return false; }
    RpcResult GetCurrentUser(UserState&) { return RpcResult::Error; }
    RpcResult Login(std::wstring const&, std::wstring const&, UserState&) { return RpcResult::Error; }
    RpcResult Logout() { return RpcResult::Error; }
    RpcResult GetLicense(LicenseState&) { return RpcResult::Error; }
    RpcResult Activate(std::wstring const&, LicenseState&) { return RpcResult::Error; }
    RpcResult GetAntivirusState(bool&) { return RpcResult::Error; }
}

#else

namespace AntivirusService
{
    namespace
    {
        bool CreateRpcBinding(RPC_BINDING_HANDLE& binding)
        {
            binding = nullptr;
            RPC_WSTR bindingString = nullptr;
            RPC_STATUS status = RpcStringBindingComposeW(
                nullptr,
                reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcProtocol)),
                nullptr,
                reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
                nullptr,
                &bindingString);
            if (status != RPC_S_OK)
            {
                return false;
            }

            status = RpcBindingFromStringBindingW(bindingString, &binding);
            RpcStringFreeW(&bindingString);
            return status == RPC_S_OK && binding != nullptr;
        }

        template <typename TFn>
        RpcResult Invoke(TFn&& fn)
        {
            __try
            {
                return FromRpcStatus(fn());
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return RpcResult::ServiceUnavailable;
            }
        }
    }

    int RunServiceMode()
    {
        return static_cast<int>(ERROR_CALL_NOT_IMPLEMENTED);
    }

    GuiStartupDecision PrepareGuiStartup()
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        if (scm == nullptr)
        {
            scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (scm == nullptr)
            {
                return GuiStartupDecision::Error;
            }
        }

        SC_HANDLE service = OpenServiceWithAccess(scm, SERVICE_QUERY_STATUS);
        DWORD openError = (service == nullptr) ? GetLastError() : ERROR_SUCCESS;
        if (service == nullptr && openError == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            service = CreateServiceIfMissing(scm);
        }
        if (service == nullptr)
        {
            service = OpenServiceWithAccess(scm, SERVICE_QUERY_STATUS | SERVICE_START);
            if (service == nullptr && GetLastError() == ERROR_ACCESS_DENIED)
            {
                if (StartServiceElevated())
                {
                    service = OpenServiceWithAccess(scm, SERVICE_QUERY_STATUS | SERVICE_START);
                    if (service == nullptr)
                    {
                        service = OpenServiceWithAccess(scm, SERVICE_QUERY_STATUS);
                    }
                }
            }
        }
        if (service == nullptr)
        {
            CloseServiceHandle(scm);
            return GuiStartupDecision::Error;
        }

        bool startedByCaller = false;
        bool running = EnsureServiceRunning(service, startedByCaller);
        if (!running)
        {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED && StartServiceElevated())
            {
                SERVICE_STATUS_PROCESS status{};
                running = WaitForServiceRunning(service, kServiceStartTimeoutMs);
                if (!running && QueryServiceStatusProcess(service, status))
                {
                    running = (status.dwCurrentState == SERVICE_RUNNING);
                }
            }
        }
        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        if (!running)
        {
            return GuiStartupDecision::Error;
        }

        return GuiStartupDecision::Continue;
    }

    bool RequestServiceStop()
    {
        RPC_BINDING_HANDLE binding = nullptr;
        if (!CreateRpcBinding(binding))
        {
            return false;
        }

        RpcResult result = Invoke([&]()
        {
            RpcStopService(binding);
            return RpcStatusOk;
        });

        RpcBindingFree(&binding);
        return result == RpcResult::Ok;
    }

    RpcResult GetCurrentUser(UserState& state)
    {
        state = {};
        RPC_BINDING_HANDLE binding = nullptr;
        if (!CreateRpcBinding(binding))
        {
            return RpcResult::ServiceUnavailable;
        }

        RpcUserInfo info{};
        RpcResult result = Invoke([&]()
        {
            return RpcGetCurrentUser(binding, &info);
        });
        RpcBindingFree(&binding);

        if (result == RpcResult::Ok)
        {
            state.authenticated = info.authenticated != 0;
            state.login = info.login;
        }
        return result;
    }

    RpcResult Login(std::wstring const& login, std::wstring const& password, UserState& state)
    {
        state = {};
        RPC_BINDING_HANDLE binding = nullptr;
        if (!CreateRpcBinding(binding))
        {
            return RpcResult::ServiceUnavailable;
        }

        RpcUserInfo info{};
        RpcResult result = Invoke([&]()
        {
            return RpcLogin(binding, login.c_str(), password.c_str(), &info);
        });
        RpcBindingFree(&binding);

        if (result == RpcResult::Ok)
        {
            state.authenticated = info.authenticated != 0;
            state.login = info.login;
        }
        return result;
    }

    RpcResult Logout()
    {
        RPC_BINDING_HANDLE binding = nullptr;
        if (!CreateRpcBinding(binding))
        {
            return RpcResult::ServiceUnavailable;
        }

        RpcResult result = Invoke([&]()
        {
            return RpcLogout(binding);
        });
        RpcBindingFree(&binding);
        return result;
    }

    RpcResult GetLicense(LicenseState& state)
    {
        state = {};
        RPC_BINDING_HANDLE binding = nullptr;
        if (!CreateRpcBinding(binding))
        {
            return RpcResult::ServiceUnavailable;
        }

        RpcLicenseInfo info{};
        RpcResult result = Invoke([&]()
        {
            return RpcGetLicense(binding, &info);
        });
        RpcBindingFree(&binding);

        if (result == RpcResult::Ok)
        {
            state.hasLicense = info.hasLicense != 0;
            state.blocked = info.blocked != 0;
            state.expiresAt = info.expiresAt;
            state.productName = info.productName;
        }
        return result;
    }

    RpcResult Activate(std::wstring const& activationCode, LicenseState& state)
    {
        state = {};
        RPC_BINDING_HANDLE binding = nullptr;
        if (!CreateRpcBinding(binding))
        {
            return RpcResult::ServiceUnavailable;
        }

        RpcLicenseInfo info{};
        RpcResult result = Invoke([&]()
        {
            return RpcActivate(binding, activationCode.c_str(), &info);
        });
        RpcBindingFree(&binding);

        if (result == RpcResult::Ok)
        {
            state.hasLicense = info.hasLicense != 0;
            state.blocked = info.blocked != 0;
            state.expiresAt = info.expiresAt;
            state.productName = info.productName;
        }
        return result;
    }

    RpcResult GetAntivirusState(bool& enabled)
    {
        enabled = false;
        RPC_BINDING_HANDLE binding = nullptr;
        if (!CreateRpcBinding(binding))
        {
            return RpcResult::ServiceUnavailable;
        }

        int flag = 0;
        RpcResult result = Invoke([&]()
        {
            return RpcGetAntivirusState(binding, &flag);
        });
        RpcBindingFree(&binding);

        if (result == RpcResult::Ok)
        {
            enabled = flag != 0;
        }
        return result;
    }
}

#endif

namespace AntivirusService
{
    wchar_t const* GetRpcResultMessage(RpcResult result)
    {
        switch (result)
        {
        case RpcResult::Ok:
            return L"\u041E\u043F\u0435\u0440\u0430\u0446\u0438\u044F \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0430";
        case RpcResult::Unauthorized:
            return L"\u041E\u0448\u0438\u0431\u043A\u0430 \u0430\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u0438";
        case RpcResult::NoLicense:
            return L"\u041B\u0438\u0446\u0435\u043D\u0437\u0438\u044F \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442";
        case RpcResult::InvalidArgument:
            return L"\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0435 \u0434\u0430\u043D\u043D\u044B\u0435";
        case RpcResult::Network:
            return L"\u041E\u0448\u0438\u0431\u043A\u0430 \u0441\u0435\u0442\u0438";
        case RpcResult::Conflict:
            return L"\u041A\u043E\u043D\u0444\u043B\u0438\u043A\u0442";
        case RpcResult::ServiceUnavailable:
            return L"\u0421\u043B\u0443\u0436\u0431\u0430 \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u043D\u0430";
        case RpcResult::Error:
        default:
            return L"\u0412\u043D\u0443\u0442\u0440\u0435\u043D\u043D\u044F\u044F \u043E\u0448\u0438\u0431\u043A\u0430";
        }
    }
}
