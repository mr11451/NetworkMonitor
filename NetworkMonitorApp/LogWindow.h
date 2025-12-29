#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>

// 前方宣言（循環参照を避けるため）
class AppController;
class WindowPositionManager;

// カスタムメッセージ
#define WM_ADD_LOG (WM_USER + 100)

class LogWindow
{
public:
    static LogWindow& GetInstance();
    
    bool Create(HWND hParent = nullptr);
    void Show();
    void Hide();
    void Clear();
    void AddLog(const std::wstring& message);
    void AddLogThreadSafe(const std::wstring& message);
    void UpdateLogFilePath(const std::wstring& directory);
    
    HWND GetHWnd() const { return m_hWnd; }
    std::wstring GetLogFilePath() const 
    { 
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_logFilePath; 
    }

private:
    LogWindow();
    ~LogWindow();
    LogWindow(const LogWindow&) = delete;
    LogWindow& operator=(const LogWindow&) = delete;

    void AddLogInternal(const std::wstring& message);
    static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

    static std::wstring LoadStringFromResource(UINT stringID);
    static const wchar_t* GetRegistryKey();

    // メンバー変数
    HWND m_hWnd;
    HWND m_hListBox;
    HWND m_hClearButton;
    HWND m_hLogPathLabel;
    HWND m_hOpenFolderButton;
    
    std::vector<std::wstring> m_logs;
    std::wstring m_logFilePath;
    mutable std::mutex m_mutex;
    
    static constexpr size_t MAX_LOG_LINES = 1000;

    // LogWindowProc.cpp のヘルパー関数に friend アクセスを許可
    friend INT_PTR CALLBACK DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
};