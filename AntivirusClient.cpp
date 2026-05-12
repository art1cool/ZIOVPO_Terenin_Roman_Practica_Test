#include <windows.h>
#include <sddl.h>

#include <string>
#include <vector>

#include "ServiceManager.h"
#include "Tray.h"

HINSTANCE g_hInst = nullptr;
HWND g_hMainWnd = nullptr;
HANDLE g_hInstanceMutex = nullptr;

namespace
{
    constexpr UINT_PTR kStatusPollTimerId = 1;
    constexpr UINT kStatusPollIntervalMs = 15000;

    enum : int
    {
        IDC_INFO_HEADER = 2001,
        IDC_INFO_USER = 2002,
        IDC_INFO_LICENSE = 2003,
        IDC_INFO_AV = 2004,

        IDC_LOGIN_LABEL = 2101,
        IDC_LOGIN_EDIT = 2102,
        IDC_PASSWORD_LABEL = 2103,
        IDC_PASSWORD_EDIT = 2104,
        IDC_LOGIN_BUTTON = 2105,

        IDC_ACTIVATE_LABEL = 2201,
        IDC_ACTIVATE_EDIT = 2202,
        IDC_ACTIVATE_BUTTON = 2203,
        IDC_LOGOUT_BUTTON = 2204
    };

    struct UiState
    {
        bool authenticated = false;
        std::wstring login;
        bool hasLicense = false;
        bool blocked = false;
        std::wstring expiresAt;
        std::wstring productName;
        bool antivirusEnabled = false;
    };

    UiState g_uiState;

    constexpr std::wstring_view kHiddenSwitches[] = {
        L"--hidden",
        L"--background",
        L"/hidden",
        L"/background"
    };

    bool ContainsSwitch(std::wstring_view commandLine, std::wstring_view value) noexcept
    {
        return commandLine.find(value) != std::wstring::npos;
    }

    bool IsHiddenStartupCommandLine() noexcept
    {
        std::wstring_view commandLine = GetCommandLineW();
        for (auto const& token : kHiddenSwitches)
        {
            if (ContainsSwitch(commandLine, token))
            {
                return true;
            }
        }
        return false;
    }

    std::wstring BuildPerUserMutexName()
    {
        constexpr wchar_t kDefaultName[] = L"Local\\AntivirusClientMutex";
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            return kDefaultName;
        }

        DWORD required = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &required);
        if (required == 0)
        {
            CloseHandle(token);
            return kDefaultName;
        }

        std::vector<BYTE> tokenInfo(required);
        if (!GetTokenInformation(token, TokenUser, tokenInfo.data(), required, &required))
        {
            CloseHandle(token);
            return kDefaultName;
        }
        CloseHandle(token);

        auto const* tokenUser = reinterpret_cast<TOKEN_USER const*>(tokenInfo.data());
        LPWSTR sidString = nullptr;
        if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sidString) || sidString == nullptr)
        {
            return kDefaultName;
        }

        std::wstring mutexName = L"Local\\AntivirusClientMutex.";
        mutexName.append(sidString);
        LocalFree(sidString);
        return mutexName;
    }

    std::wstring GetControlText(HWND hwnd, int controlId)
    {
        HWND control = GetDlgItem(hwnd, controlId);
        if (control == nullptr)
        {
            return {};
        }

        int length = GetWindowTextLengthW(control);
        if (length <= 0)
        {
            return {};
        }

        std::wstring text(static_cast<size_t>(length), L'\0');
        GetWindowTextW(control, text.data(), length + 1);
        return text;
    }

    void SetControlText(HWND hwnd, int controlId, std::wstring const& text)
    {
        HWND control = GetDlgItem(hwnd, controlId);
        if (control != nullptr)
        {
            SetWindowTextW(control, text.c_str());
        }
    }

    void SetControlVisibility(HWND hwnd, int controlId, bool visible)
    {
        HWND control = GetDlgItem(hwnd, controlId);
        if (control != nullptr)
        {
            ShowWindow(control, visible ? SW_SHOW : SW_HIDE);
        }
    }

    void UpdateInfoLabels(HWND hwnd)
    {
        SetControlText(hwnd, IDC_INFO_HEADER, L"\u0421\u043E\u0441\u0442\u043E\u044F\u043D\u0438\u0435 \u0441\u043B\u0443\u0436\u0431\u044B \u0438 \u043B\u0438\u0446\u0435\u043D\u0437\u0438\u0438");

        if (!g_uiState.authenticated)
        {
            SetControlText(hwnd, IDC_INFO_USER, L"\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C: \u043D\u0435 \u0430\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u0446\u0438\u0440\u043E\u0432\u0430\u043D");
            SetControlText(hwnd, IDC_INFO_LICENSE, L"\u041B\u0438\u0446\u0435\u043D\u0437\u0438\u044F: \u043E\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442");
            SetControlText(hwnd, IDC_INFO_AV, L"\u0410\u043D\u0442\u0438\u0432\u0438\u0440\u0443\u0441: \u0437\u0430\u0431\u043B\u043E\u043A\u0438\u0440\u043E\u0432\u0430\u043D");
            return;
        }

        std::wstring user = L"\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C: " + g_uiState.login;
        SetControlText(hwnd, IDC_INFO_USER, user);

        if (!g_uiState.hasLicense)
        {
            SetControlText(hwnd, IDC_INFO_LICENSE, L"\u041B\u0438\u0446\u0435\u043D\u0437\u0438\u044F: \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F \u0430\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u044F");
            SetControlText(hwnd, IDC_INFO_AV, L"\u0410\u043D\u0442\u0438\u0432\u0438\u0440\u0443\u0441: \u0437\u0430\u0431\u043B\u043E\u043A\u0438\u0440\u043E\u0432\u0430\u043D");
            return;
        }

        std::wstring license = L"\u041B\u0438\u0446\u0435\u043D\u0437\u0438\u044F: ";
        license += g_uiState.productName.empty() ? L"\u0430\u043A\u0442\u0438\u0432\u043D\u0430" : g_uiState.productName;
        if (!g_uiState.expiresAt.empty())
        {
            license += L", \u0434\u043E ";
            license += g_uiState.expiresAt;
        }
        SetControlText(hwnd, IDC_INFO_LICENSE, license);

        if (g_uiState.blocked || !g_uiState.antivirusEnabled)
        {
            SetControlText(hwnd, IDC_INFO_AV, L"\u0410\u043D\u0442\u0438\u0432\u0438\u0440\u0443\u0441: \u0437\u0430\u0431\u043B\u043E\u043A\u0438\u0440\u043E\u0432\u0430\u043D");
        }
        else
        {
            SetControlText(hwnd, IDC_INFO_AV, L"\u0410\u043D\u0442\u0438\u0432\u0438\u0440\u0443\u0441: \u0440\u0430\u0437\u0431\u043B\u043E\u043A\u0438\u0440\u043E\u0432\u0430\u043D");
        }
    }

    void UpdateUiMode(HWND hwnd)
    {
        bool showLogin = !g_uiState.authenticated;
        bool showActivation = g_uiState.authenticated && !g_uiState.hasLicense;

        SetControlVisibility(hwnd, IDC_LOGIN_LABEL, showLogin);
        SetControlVisibility(hwnd, IDC_LOGIN_EDIT, showLogin);
        SetControlVisibility(hwnd, IDC_PASSWORD_LABEL, showLogin);
        SetControlVisibility(hwnd, IDC_PASSWORD_EDIT, showLogin);
        SetControlVisibility(hwnd, IDC_LOGIN_BUTTON, showLogin);

        SetControlVisibility(hwnd, IDC_ACTIVATE_LABEL, showActivation);
        SetControlVisibility(hwnd, IDC_ACTIVATE_EDIT, showActivation);
        SetControlVisibility(hwnd, IDC_ACTIVATE_BUTTON, showActivation);
        SetControlVisibility(hwnd, IDC_LOGOUT_BUTTON, g_uiState.authenticated);

        UpdateInfoLabels(hwnd);
    }

    void RefreshStateFromService(HWND hwnd)
    {
        AntivirusService::UserState user{};
        AntivirusService::RpcResult userResult = AntivirusService::GetCurrentUser(user);
        if (userResult != AntivirusService::RpcResult::Ok)
        {
            MessageBoxW(hwnd, AntivirusService::GetRpcResultMessage(userResult), L"\u041E\u0448\u0438\u0431\u043A\u0430 RPC", MB_OK | MB_ICONERROR);
            return;
        }

        g_uiState = {};
        g_uiState.authenticated = user.authenticated;
        g_uiState.login = user.login;

        if (g_uiState.authenticated)
        {
            AntivirusService::LicenseState license{};
            AntivirusService::RpcResult licenseResult = AntivirusService::GetLicense(license);
            if (licenseResult == AntivirusService::RpcResult::Ok)
            {
                g_uiState.hasLicense = license.hasLicense;
                g_uiState.blocked = license.blocked;
                g_uiState.expiresAt = license.expiresAt;
                g_uiState.productName = license.productName;

                bool enabled = false;
                AntivirusService::RpcResult avResult = AntivirusService::GetAntivirusState(enabled);
                g_uiState.antivirusEnabled = (avResult == AntivirusService::RpcResult::Ok) && enabled;
            }
            else if (licenseResult == AntivirusService::RpcResult::NoLicense)
            {
                g_uiState.hasLicense = false;
            }
            else
            {
                MessageBoxW(hwnd, AntivirusService::GetRpcResultMessage(licenseResult), L"\u041B\u0438\u0446\u0435\u043D\u0437\u0438\u044F", MB_OK | MB_ICONWARNING);
            }
        }

        UpdateUiMode(hwnd);
    }

    void CreateMainControls(HWND hwnd)
    {
        HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        auto create = [&](wchar_t const* cls, wchar_t const* text, DWORD style, int x, int y, int w, int h, int id)
        {
            HWND c = CreateWindowExW(0, cls, text, style, x, y, w, h, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_hInst, nullptr);
            if (c != nullptr)
            {
                SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            }
            return c;
        };

        create(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 20, 540, 20, IDC_INFO_HEADER);
        create(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 50, 540, 20, IDC_INFO_USER);
        create(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 75, 540, 20, IDC_INFO_LICENSE);
        create(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 20, 100, 540, 20, IDC_INFO_AV);

        create(L"STATIC", L"\u041B\u043E\u0433\u0438\u043D (email):", WS_CHILD | WS_VISIBLE, 20, 150, 150, 20, IDC_LOGIN_LABEL);
        create(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 180, 147, 250, 24, IDC_LOGIN_EDIT);
        create(L"STATIC", L"\u041F\u0430\u0440\u043E\u043B\u044C:", WS_CHILD | WS_VISIBLE, 20, 185, 150, 20, IDC_PASSWORD_LABEL);
        create(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD, 180, 182, 250, 24, IDC_PASSWORD_EDIT);
        create(L"BUTTON", L"\u0412\u043E\u0439\u0442\u0438", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 440, 147, 120, 60, IDC_LOGIN_BUTTON);

        create(L"STATIC", L"\u041A\u043E\u0434 \u0430\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u0438:", WS_CHILD | WS_VISIBLE, 20, 150, 150, 20, IDC_ACTIVATE_LABEL);
        create(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 180, 147, 250, 24, IDC_ACTIVATE_EDIT);
        create(L"BUTTON", L"\u0410\u043A\u0442\u0438\u0432\u0438\u0440\u043E\u0432\u0430\u0442\u044C", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 440, 147, 120, 24, IDC_ACTIVATE_BUTTON);
        create(L"BUTTON", L"\u0412\u044B\u0439\u0442\u0438 \u0438\u0437 \u0430\u043A\u043A\u0430\u0443\u043D\u0442\u0430", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 440, 182, 120, 24, IDC_LOGOUT_BUTTON);
    }

    void HandleLogin(HWND hwnd)
    {
        std::wstring login = GetControlText(hwnd, IDC_LOGIN_EDIT);
        std::wstring password = GetControlText(hwnd, IDC_PASSWORD_EDIT);
        if (login.empty() || password.empty())
        {
            MessageBoxW(hwnd, L"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043B\u043E\u0433\u0438\u043D \u0438 \u043F\u0430\u0440\u043E\u043B\u044C", L"\u0410\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u044F", MB_OK | MB_ICONWARNING);
            return;
        }

        AntivirusService::UserState user{};
        AntivirusService::RpcResult result = AntivirusService::Login(login, password, user);
        if (result != AntivirusService::RpcResult::Ok)
        {
            MessageBoxW(hwnd, AntivirusService::GetRpcResultMessage(result), L"\u0410\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u043A\u0430\u0446\u0438\u044F", MB_OK | MB_ICONERROR);
            SetControlText(hwnd, IDC_PASSWORD_EDIT, L"");
            return;
        }

        SetControlText(hwnd, IDC_PASSWORD_EDIT, L"");
        RefreshStateFromService(hwnd);
    }

    void HandleActivate(HWND hwnd)
    {
        std::wstring code = GetControlText(hwnd, IDC_ACTIVATE_EDIT);
        if (code.empty())
        {
            MessageBoxW(hwnd, L"\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043A\u043E\u0434 \u0430\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u0438", L"\u0410\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u044F", MB_OK | MB_ICONWARNING);
            return;
        }

        AntivirusService::LicenseState license{};
        AntivirusService::RpcResult result = AntivirusService::Activate(code, license);
        if (result != AntivirusService::RpcResult::Ok)
        {
            MessageBoxW(hwnd, AntivirusService::GetRpcResultMessage(result), L"\u0410\u043A\u0442\u0438\u0432\u0430\u0446\u0438\u044F", MB_OK | MB_ICONERROR);
            return;
        }

        RefreshStateFromService(hwnd);
    }

    void HandleLogout(HWND hwnd)
    {
        AntivirusService::RpcResult result = AntivirusService::Logout();
        if (result != AntivirusService::RpcResult::Ok)
        {
            MessageBoxW(hwnd, AntivirusService::GetRpcResultMessage(result), L"\u0412\u044B\u0445\u043E\u0434", MB_OK | MB_ICONWARNING);
            return;
        }

        SetControlText(hwnd, IDC_LOGIN_EDIT, L"");
        SetControlText(hwnd, IDC_PASSWORD_EDIT, L"");
        SetControlText(hwnd, IDC_ACTIVATE_EDIT, L"");
        RefreshStateFromService(hwnd);
    }
}

BOOL InitInstance(HINSTANCE hInstance);
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
BOOL CheckSingleInstance();

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow)
{
    if (!CheckSingleInstance())
    {
        return 0;
    }

    AntivirusService::GuiStartupDecision startupDecision = AntivirusService::PrepareGuiStartup();
    if (startupDecision == AntivirusService::GuiStartupDecision::Exit)
    {
        return 0;
    }

    if (startupDecision == AntivirusService::GuiStartupDecision::Error)
    {
        MessageBoxW(nullptr, L"\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043F\u0440\u043E\u0432\u0435\u0440\u0438\u0442\u044C/\u0437\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0441\u043B\u0443\u0436\u0431\u0443", L"\u041E\u0448\u0438\u0431\u043A\u0430", MB_ICONERROR);
        return 0;
    }

    g_hInst = hInstance;

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = L"AntivirusClientMainWnd";

    if (!RegisterClassExW(&wc))
    {
        return 0;
    }

    if (!InitInstance(hInstance))
    {
        return 0;
    }

    if (!InitTray(g_hInst, g_hMainWnd))
    {
        MessageBoxW(nullptr, L"\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u0441\u043E\u0437\u0434\u0430\u0442\u044C \u0438\u043A\u043E\u043D\u043A\u0443 \u0432 \u0442\u0440\u0435\u0435", L"\u041E\u0448\u0438\u0431\u043A\u0430", MB_ICONERROR);
        return 0;
    }

    bool const hiddenStartup = IsHiddenStartupCommandLine();
    if (!hiddenStartup)
    {
        ShowWindow(g_hMainWnd, nCmdShow == SW_SHOWMINIMIZED ? SW_SHOWMINIMIZED : SW_SHOW);
        UpdateWindow(g_hMainWnd);
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}

BOOL InitInstance(HINSTANCE hInstance)
{
    g_hMainWnd = CreateWindowExW(
        0,
        L"AntivirusClientMainWnd",
        L"Antivirus Client",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 620, 360,
        nullptr, nullptr, hInstance, nullptr);

    return g_hMainWnd != nullptr;
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HMENU hMenuBar = CreateMenu();
        HMENU hFileMenu = CreatePopupMenu();
        AppendMenuW(hFileMenu, MF_STRING, IDM_TRAY_EXIT, L"\u0412\u044B\u0445\u043E\u0434");
        AppendMenuW(hMenuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(hFileMenu), L"\u0424\u0430\u0439\u043B");
        SetMenu(hwnd, hMenuBar);

        CreateMainControls(hwnd);
        SetTimer(hwnd, kStatusPollTimerId, kStatusPollIntervalMs, nullptr);
        RefreshStateFromService(hwnd);
        return 0;
    }

    case WM_TIMER:
        if (wParam == kStatusPollTimerId)
        {
            RefreshStateFromService(hwnd);
            return 0;
        }
        break;

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);
        if (id == IDM_TRAY_EXIT)
        {
            if (!AntivirusService::RequestServiceStop())
            {
                MessageBoxW(hwnd, L"\u041D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C \u043E\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u044C \u0441\u043B\u0443\u0436\u0431\u0443. \u041F\u0440\u0438\u043B\u043E\u0436\u0435\u043D\u0438\u0435 \u043E\u0441\u0442\u0430\u043D\u0435\u0442\u0441\u044F \u0437\u0430\u043F\u0443\u0449\u0435\u043D\u043D\u044B\u043C.", L"AntivirusClient", MB_OK | MB_ICONWARNING);
                return 0;
            }
            DestroyWindow(hwnd);
            return 0;
        }
        if (id == IDC_LOGIN_BUTTON)
        {
            HandleLogin(hwnd);
            return 0;
        }
        if (id == IDC_ACTIVATE_BUTTON)
        {
            HandleActivate(hwnd);
            return 0;
        }
        if (id == IDC_LOGOUT_BUTTON)
        {
            HandleLogout(hwnd);
            return 0;
        }
        break;
    }

    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
        {
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }
        break;

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, kStatusPollTimerId);
        ShutdownTray();
        if (g_hInstanceMutex != nullptr)
        {
            ReleaseMutex(g_hInstanceMutex);
            CloseHandle(g_hInstanceMutex);
            g_hInstanceMutex = nullptr;
        }
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

BOOL CheckSingleInstance()
{
    std::wstring mutexName = BuildPerUserMutexName();
    g_hInstanceMutex = CreateMutexW(nullptr, TRUE, mutexName.c_str());
    if (g_hInstanceMutex == nullptr)
    {
        return FALSE;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(g_hInstanceMutex);
        g_hInstanceMutex = nullptr;
        return FALSE;
    }

    return TRUE;
}
