#include "framework.h"
#include "UIHelper.h"
#include "AppConstants.h"
#include "Resource.h"
#include <sstream>

extern HINSTANCE hInst;

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
    WCHAR buffer[AppConstants::MAX_PORT_STRING_LENGTH] = { 0 };
    GetDlgItemTextW(hDlg, controlID, buffer, AppConstants::MAX_PORT_STRING_LENGTH);
    
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
    WCHAR buffer[AppConstants::MAX_PORT_STRING_LENGTH];
    swprintf_s(buffer, AppConstants::MAX_PORT_STRING_LENGTH, L"%u", port);
    SetDlgItemTextW(hDlg, controlID, buffer);
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