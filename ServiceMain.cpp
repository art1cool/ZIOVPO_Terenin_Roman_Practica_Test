#include <windows.h>

#include "ServiceManager.h"

int __stdcall wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    return AntivirusService::RunServiceMode();
}
