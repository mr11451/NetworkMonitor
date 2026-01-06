#include "framework.h"
#include "UIHelper.h"
#include "AppConstants.h"
#include "Resource.h"
#include <sstream>
#include <ws2tcpip.h>
#include <algorithm>
#include <string>
#include <cstdlib>
#include <Windows.h>
#include <ws2ipdef.h>
#include <ws2def.h>
#include <cctype>
#include <in6addr.h>
#include <cstdio>

#pragma comment(lib, "ws2_32.lib")

extern HINSTANCE hInst;

constexpr auto MAX_PORT_STRING_LENGTH = 6; // 65535 + null終端で6文字
constexpr auto MAX_IP_STRING_LENGTH = 46;  // IPv6の最大長 + null終端

std::wstring UIHelper::LoadStringFromResource(UINT stringID)
{
    WCHAR buffer[AppConstants::MAX_STRING_LENGTH];
    if (LoadStringW(hInst, stringID, buffer, AppConstants::MAX_STRING_LENGTH) > 0)
    {
        return std::wstring(buffer);
    }
    return L"";
}

USHORT UIHelper::GetPortFromEditControl(HWND hDlg, UINT controlID)
{
    WCHAR buffer[MAX_PORT_STRING_LENGTH] = { 0 };
    GetDlgItemTextW(hDlg, controlID, buffer, MAX_PORT_STRING_LENGTH);

    int port = _wtoi(buffer);

    // ポート番号の妥当性チェック
    if (port < AppConstants::MIN_PORT || port > AppConstants::MAX_PORT)
    {
        ShowErrorMessage(hDlg, IDS_ERROR_PORT_RANGE, IDS_ERROR_TITLE);
        return 0;
    }

    return static_cast<USHORT>(port);
}

void UIHelper::SetPortToEditControl(HWND hDlg, UINT controlID, USHORT port)
{
    WCHAR buffer[MAX_PORT_STRING_LENGTH];
    swprintf_s(buffer, MAX_PORT_STRING_LENGTH, L"%u", port);
    SetDlgItemTextW(hDlg, controlID, buffer);
}

std::wstring UIHelper::GetIPAddressFromEditControl(HWND hDlg, UINT controlID)
{
    WCHAR buffer[MAX_IP_STRING_LENGTH] = { 0 };
    GetDlgItemTextW(hDlg, controlID, buffer, MAX_IP_STRING_LENGTH);
    
    std::wstring ipAddress(buffer);
    
    // トリム（前後の空白を削除）
    size_t start = ipAddress.find_first_not_of(L" \t\r\n");
    size_t end = ipAddress.find_last_not_of(L" \t\r\n");
    
    if (start == std::wstring::npos)
    {
        return L""; // 空文字列または空白のみ
    }
    
    ipAddress = ipAddress.substr(start, end - start + 1);
    
    // 空の場合は有効（全IP対象）
    if (ipAddress.empty())
    {
        return L"";
    }
    
    // IPアドレスの妥当性を検証
    if (!ValidateIPAddress(ipAddress))
    {
        ShowErrorMessage(hDlg, IDS_ERROR_INVALID_IP, IDS_ERROR_TITLE);
        return L"";
    }
    
    return ipAddress;
}

void UIHelper::SetIPAddressToEditControl(HWND hDlg, UINT controlID, const std::wstring& ipAddress)
{
    SetDlgItemTextW(hDlg, controlID, ipAddress.c_str());
}

bool UIHelper::ValidateIPAddress(const std::wstring& ipAddress)
{
    if (ipAddress.empty())
    {
        return true; // 空文字列は有効（全IP対象）
    }
    
    // 小文字に変換して比較
    std::wstring lowerIP = ipAddress;
    std::transform(lowerIP.begin(), lowerIP.end(), lowerIP.begin(), ::towlower);
    
    // "localhost" は有効（ループバックアドレス）
    if (lowerIP == L"localhost")
    {
        return true;
    }
    
    // "127.0.0.1" (IPv4ループバック) も明示的に許可
    if (ipAddress == L"127.0.0.1")
    {
        return true;
    }
    
    // "::1" (IPv6ループバック) も明示的に許可
    if (ipAddress == L"::1")
    {
        return true;
    }
    
    // IPv4の検証
    char ipv4Buffer[INET_ADDRSTRLEN];
    int result = WideCharToMultiByte(CP_UTF8, 0, ipAddress.c_str(), -1, 
                                     ipv4Buffer, INET_ADDRSTRLEN, NULL, NULL);
    
    if (result > 0)
    {
        struct in_addr addr4 {};
        if (inet_pton(AF_INET, ipv4Buffer, &addr4) == 1)
        {
            return true; // 有効なIPv4アドレス
        }
    }
    
    // IPv6の検証
    char ipv6Buffer[INET6_ADDRSTRLEN];
    result = WideCharToMultiByte(CP_UTF8, 0, ipAddress.c_str(), -1, 
                                 ipv6Buffer, INET6_ADDRSTRLEN, NULL, NULL);
    
    if (result > 0)
    {
        struct in6_addr addr6 {};
        if (inet_pton(AF_INET6, ipv6Buffer, &addr6) == 1)
        {
            return true; // 有効なIPv6アドレス
        }
    }
    
    return false; // 無効なIPアドレス
}

std::wstring UIHelper::ResolveIPAddress(const std::wstring& ipAddress)
{
    if (ipAddress.empty())
    {
        return L""; // 空文字列はそのまま返す（全IP対象）
    }
    
    // 小文字に変換して比較
    std::wstring lowerIP = ipAddress;
    std::transform(lowerIP.begin(), lowerIP.end(), lowerIP.begin(), ::towlower);
    
    // "localhost" を "127.0.0.1" に変換
    if (lowerIP == L"localhost")
    {
        return L"127.0.0.1";
    }
    
    // それ以外はそのまま返す
    return ipAddress;
}

IPAddressType UIHelper::GetIPAddressType(const std::wstring& ipAddress)
{
    if (ipAddress.empty())
    {
        return IPAddressType::None; // 空文字列（全IP対象）
    }
    
    // 小文字に変換
    std::wstring lowerIP = ipAddress;
    std::transform(lowerIP.begin(), lowerIP.end(), lowerIP.begin(), ::towlower);
    
    // "localhost" はIPv4として扱う（127.0.0.1）
    if (lowerIP == L"localhost")
    {
        return IPAddressType::IPv4;
    }
    
    // IPv4の検証
    char ipv4Buffer[INET_ADDRSTRLEN];
    int result = WideCharToMultiByte(CP_UTF8, 0, ipAddress.c_str(), -1, 
                                     ipv4Buffer, INET_ADDRSTRLEN, NULL, NULL);
    
    if (result > 0)
    {
        struct in_addr addr4 {};
        if (inet_pton(AF_INET, ipv4Buffer, &addr4) == 1)
        {
            return IPAddressType::IPv4;
        }
    }
    
    // IPv6の検証
    char ipv6Buffer[INET6_ADDRSTRLEN];
    result = WideCharToMultiByte(CP_UTF8, 0, ipAddress.c_str(), -1, 
                                 ipv6Buffer, INET6_ADDRSTRLEN, NULL, NULL);
    
    if (result > 0)
    {
        struct in6_addr addr6 {};
        if (inet_pton(AF_INET6, ipv6Buffer, &addr6) == 1)
        {
            return IPAddressType::IPv6;
        }
    }
    
    return IPAddressType::None;
}

void UIHelper::UpdateStatusText(HWND hDlg, UINT controlID, bool isCapturing, int packetCount)
{
    std::wstringstream ss;
    
    // 状態
    ss << L"状態: " << (isCapturing ? 
        LoadStringFromResource(IDS_STATUS_RUNNING) : 
        LoadStringFromResource(IDS_STATUS_STOPPED)) << L"\r\n";
    
    // パケット数
    WCHAR packetCountText[AppConstants::MAX_STRING_LENGTH];
    swprintf_s(packetCountText, AppConstants::MAX_STRING_LENGTH,
        LoadStringFromResource(IDS_STATUS_PACKET_COUNT).c_str(),
        packetCount);
    ss << packetCountText << L"\r\n\r\n";
    
    // 使い方
    ss << LoadStringFromResource(IDS_STATUS_USAGE) << L"\r\n\r\n";
    
    // 管理者権限の注意
    ss << LoadStringFromResource(IDS_STATUS_ADMIN_REQUIRED);

    SetDlgItemTextW(hDlg, controlID, ss.str().c_str());
}

bool UIHelper::ShowConfirmDialog(HWND hDlg, UINT messageID, UINT titleID)
{
    int result = MessageBoxW(hDlg,
        LoadStringFromResource(messageID).c_str(),
        LoadStringFromResource(titleID).c_str(),
        MB_YESNO | MB_ICONQUESTION);
    return (result == IDYES);
}

void UIHelper::ShowInfoMessage(HWND hDlg, const std::wstring& message, UINT titleID)
{
    MessageBoxW(hDlg,
        message.c_str(),
        LoadStringFromResource(titleID).c_str(),
        MB_OK | MB_ICONINFORMATION);
}

void UIHelper::ShowErrorMessage(HWND hDlg, UINT messageID, UINT titleID)
{
    MessageBoxW(hDlg,
        LoadStringFromResource(messageID).c_str(),
        LoadStringFromResource(titleID).c_str(),
        MB_OK | MB_ICONERROR);
}