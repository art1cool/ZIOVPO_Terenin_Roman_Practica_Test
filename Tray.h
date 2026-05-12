#pragma once
#include <windows.h>

BOOL InitTray(HINSTANCE hInst, HWND hMainWnd);
BOOL AddTrayIcon(HWND hwnd);
BOOL RemoveTrayIcon();
void ShutdownTray();
void ShowTrayContextMenu(HWND hwnd);

#define IDM_TRAY_OPEN       1001
#define IDM_TRAY_EXIT       1002
