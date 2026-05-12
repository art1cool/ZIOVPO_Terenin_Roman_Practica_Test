#include "Tray.h"
#include <shellapi.h>

static NOTIFYICONDATAW nid = {};
static HMENU g_hTrayMenu = nullptr;
static HWND  g_hTrayWnd = nullptr;
static UINT  WM_TASKBARCREATED = 0;
static constexpr UINT kTrayCallbackMessage = WM_APP + 1;

LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

static HMENU CreateTrayMenu()
{
    HMENU hMenu = CreatePopupMenu();
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_OPEN, L"\u041E\u0442\u043A\u0440\u044B\u0442\u044C");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, IDM_TRAY_EXIT, L"\u0412\u044B\u0445\u043E\u0434");
    return hMenu;
}

BOOL InitTray(HINSTANCE hInst, HWND hMainWnd)
{
    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = TrayWndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"TrayHiddenWindowClass";

    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
    {
        return FALSE;
    }

    g_hTrayWnd = CreateWindowExW(0, L"TrayHiddenWindowClass", L"",
        WS_POPUP, 0, 0, 0, 0,
        nullptr, nullptr, hInst, nullptr);
    if (!g_hTrayWnd)
    {
        return FALSE;
    }

    SetWindowLongPtrW(g_hTrayWnd, GWLP_USERDATA, (LONG_PTR)hMainWnd);

    g_hTrayMenu = CreateTrayMenu();
    if (!g_hTrayMenu)
    {
        DestroyWindow(g_hTrayWnd);
        g_hTrayWnd = nullptr;
        return FALSE;
    }

    return AddTrayIcon(g_hTrayWnd);
}

BOOL AddTrayIcon(HWND hwnd)
{
    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = kTrayCallbackMessage;
    nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wcscpy_s(nid.szTip, L"Antivirus Client");

    return Shell_NotifyIconW(NIM_ADD, &nid);
}

BOOL RemoveTrayIcon()
{
    return Shell_NotifyIconW(NIM_DELETE, &nid);
}

void ShutdownTray()
{
    RemoveTrayIcon();

    if (g_hTrayMenu != nullptr)
    {
        DestroyMenu(g_hTrayMenu);
        g_hTrayMenu = nullptr;
    }

    if (g_hTrayWnd != nullptr)
    {
        DestroyWindow(g_hTrayWnd);
        g_hTrayWnd = nullptr;
    }
}

void ShowTrayContextMenu(HWND hwnd)
{
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(g_hTrayMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt.x, pt.y, 0, hwnd, nullptr);
    PostMessageW(hwnd, WM_NULL, 0, 0);
}

LRESULT CALLBACK TrayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HWND hMainWnd = (HWND)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    if (msg == WM_TASKBARCREATED)
    {
        AddTrayIcon(hwnd);
        return 0;
    }

    if (msg == kTrayCallbackMessage)
    {
        if (lParam == WM_LBUTTONDOWN)
        {
            if (hMainWnd)
            {
                ShowWindow(hMainWnd, SW_SHOW);
                SetForegroundWindow(hMainWnd);
            }
        }
        else if (lParam == WM_RBUTTONDOWN)
        {
            ShowTrayContextMenu(hwnd);
        }

        return 0;
    }

    if (msg == WM_COMMAND)
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDM_TRAY_OPEN:
            if (hMainWnd)
            {
                ShowWindow(hMainWnd, SW_SHOW);
                SetForegroundWindow(hMainWnd);
            }
            break;

        case IDM_TRAY_EXIT:
            if (hMainWnd)
            {
                PostMessageW(hMainWnd, WM_COMMAND, MAKEWPARAM(IDM_TRAY_EXIT, 0), 0);
            }
            else
            {
                PostQuitMessage(0);
            }
            break;
        }

        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
