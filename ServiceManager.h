#pragma once

#include <string>

namespace AntivirusService
{
    enum class GuiStartupDecision
    {
        Continue,
        Exit,
        Error
    };

    enum class RpcResult
    {
        Ok = 0,
        Error = 1,
        Unauthorized = 2,
        NoLicense = 3,
        InvalidArgument = 4,
        Network = 5,
        Conflict = 6,
        ServiceUnavailable = 7
    };

    struct UserState
    {
        bool authenticated = false;
        std::wstring login;
    };

    struct LicenseState
    {
        bool hasLicense = false;
        bool blocked = false;
        std::wstring expiresAt;
        std::wstring productName;
    };

    GuiStartupDecision PrepareGuiStartup();
    bool RequestServiceStop();
    int RunServiceMode();

    RpcResult GetCurrentUser(UserState& state);
    RpcResult Login(std::wstring const& login, std::wstring const& password, UserState& state);
    RpcResult Logout();
    RpcResult GetLicense(LicenseState& state);
    RpcResult Activate(std::wstring const& activationCode, LicenseState& state);
    RpcResult GetAntivirusState(bool& enabled);

    wchar_t const* GetRpcResultMessage(RpcResult result);
}
