#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <mutex>

class LogWindow
{
public:
    static LogWindow& GetInstance()
    {
        static LogWindow instance;
        return instance;
    }

    // ウィンドウ管理
    bool Create(HWND hParent);
    void Show();
    void Hide();
    bool IsVisible() const { return m_isVisible; }
    
    // ログ管理
    void AddLog(const std::wstring& message);
    void AddLogThreadSafe(const std::wstring& message);
    void AddLogThreadSafe(const SYSTEMTIME& timestamp, const std::wstring& message);
    void Clear();
    
    // ログファイルパス管理
    void UpdateLogFilePath(const std::wstring& directory);
    std::wstring GetLogFilePath() const;

private:
    LogWindow();
    ~LogWindow();
    LogWindow(const LogWindow&) = delete;
    LogWindow& operator=(const LogWindow&) = delete;

    // ウィンドウプロシージャ - publicではなくフレンド関数として扱う
    static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
    
    // 内部ヘルパー
    std::wstring CreateLogEntry(const std::wstring& message) const;
    void HandleClearButton();
    void HandleOpenFolderButton();
    std::wstring LoadStringFromResource(int stringId) const;
    std::wstring GetRegistryKey() const;

    // カスタムメッセージ - #defineに変更
    static constexpr size_t MAX_LOG_LINES = 1000;

    // メンバー変数
    HWND m_hWnd;
    HWND m_hParent;
    HWND m_hListBox;
    HWND m_hLogPathLabel;
    HWND m_hClearButton;
    HWND m_hOpenFolderButton;
    bool m_isVisible;
    std::vector<std::wstring> m_logs;
    std::wstring m_logFilePath;
    mutable std::mutex m_mutex;

protected:
    void AddLogInternal(const std::wstring& message);
    
    // DlgProcからアクセスできるようフレンド宣言
    friend INT_PTR CALLBACK DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
};

// WM_ADD_LOGを#defineマクロとして定義（constexprではswitch文で使えない）
#define WM_ADD_LOG (WM_USER + 100)