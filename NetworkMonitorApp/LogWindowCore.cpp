#include "framework.h"
#include "LogWindow.h"
#include "Resource.h"

void LogWindow::AddLog(const std::wstring& message)
{
    AddLogInternal(message);
}

void LogWindow::AddLogThreadSafe(const std::wstring& message)
{
    if (m_hWnd && IsWindow(m_hWnd))
    {
        std::wstring* pMessage = new std::wstring(message);
        PostMessage(m_hWnd, WM_ADD_LOG, 0, reinterpret_cast<LPARAM>(pMessage));
    }
}

void LogWindow::AddLogInternal(const std::wstring& message)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // 最大ログ行数チェック
    if (m_logs.size() >= MAX_LOG_LINES)
    {
        m_logs.erase(m_logs.begin());
        if (m_hListBox && IsWindow(m_hListBox))
        {
            SendMessage(m_hListBox, LB_DELETESTRING, 0, 0);
        }
    }

    // タイムスタンプ付きログエントリ作成
    std::wstring logEntry = CreateLogEntry(message);
    m_logs.push_back(logEntry);

    // リストボックスに追加
    if (m_hListBox && IsWindow(m_hListBox))
    {
        int index = static_cast<int>(SendMessage(m_hListBox, LB_ADDSTRING, 0, 
                                                  reinterpret_cast<LPARAM>(logEntry.c_str())));
        SendMessage(m_hListBox, LB_SETTOPINDEX, index, 0);
    }
}

std::wstring LogWindow::CreateLogEntry(const std::wstring& message) const
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    wchar_t timeStr[64];
    swprintf_s(timeStr, L"[%02d:%02d:%02d.%03d] ", 
               st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    return std::wstring(timeStr) + message;
}

void LogWindow::Clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logs.clear();
    
    if (m_hListBox && IsWindow(m_hListBox))
    {
        SendMessage(m_hListBox, LB_RESETCONTENT, 0, 0);
    }
}

void LogWindow::UpdateLogFilePath(const std::wstring& directory)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logFilePath = directory;

    if (m_hLogPathLabel && IsWindow(m_hLogPathLabel))
    {
        std::wstring displayText = LoadStringFromResource(IDS_LOG_LABEL_PATH_PREFIX) + directory;
        SetWindowTextW(m_hLogPathLabel, displayText.c_str());
    }
}