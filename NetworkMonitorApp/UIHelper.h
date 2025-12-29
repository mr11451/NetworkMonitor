#pragma once
#include <Windows.h>
#include <string>

class UIHelper
{
public:
    // リソース文字列の読み込み
    static std::wstring LoadStringFromResource(UINT stringID);
    
    // ポート番号の取得と検証
    static USHORT GetPortFromEditControl(HWND hDlg, UINT controlID);
    
    // ポート番号の設定
    static void SetPortToEditControl(HWND hDlg, UINT controlID, USHORT port);
    
    // ステータステキストの更新
    static void UpdateStatusText(HWND hDlg, UINT controlID, bool isCapturing, int packetCount);
    
    // 確認ダイアログの表示
    static bool ShowConfirmDialog(HWND hDlg, UINT messageID, UINT titleID);
    
    // 情報メッセージの表示
    static void ShowInfoMessage(HWND hDlg, const std::wstring& message, UINT titleID);
    
    // エラーメッセージの表示
    static void ShowErrorMessage(HWND hDlg, UINT messageID, UINT titleID);

private:
    UIHelper() = delete;
    ~UIHelper() = delete;
};