#pragma once
#include <string>
#include <windows.h>

// IPアドレスのタイプを表す列挙型
enum class IPAddressType
{
    None,       // 空または全IP対象
    IPv4,       // IPv4アドレス
    IPv6        // IPv6アドレス
};

class UIHelper
{
public:
    // リソース文字列の読み込み
    static std::wstring LoadStringFromResource(UINT stringID);
    
    // ポート番号の取得と検証
    static USHORT GetPortFromEditControl(HWND hDlg, UINT controlID);
    
    // ポート番号の設定
    static void SetPortToEditControl(HWND hDlg, UINT controlID, USHORT port);
    
    // IPアドレスの取得と検証
    static std::wstring GetIPAddressFromEditControl(HWND hDlg, UINT controlID);
    
    // IPアドレスの設定
    static void SetIPAddressToEditControl(HWND hDlg, UINT controlID, const std::wstring& ipAddress);
    
    // IPアドレスの妥当性検証
    static bool ValidateIPAddress(const std::wstring& ipAddress);
    
    // localhostを127.0.0.1に変換（必要に応じて）
    static std::wstring ResolveIPAddress(const std::wstring& ipAddress);
    
    // IPアドレスの種別を判定
    static IPAddressType GetIPAddressType(const std::wstring& ipAddress);
    
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