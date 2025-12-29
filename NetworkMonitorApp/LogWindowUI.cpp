#include "framework.h"
#include "LogWindow.h"
#include "resource.h"
#include "AppController.h"
#include "WindowPositionManager.h"

bool LogWindow::Create(HWND hParent)
{
    if (m_hWnd && IsWindow(m_hWnd))
    {
        return true;
    }

    // ダイアログリソースからウィンドウを作成
    m_hWnd = CreateDialogParam(
        GetModuleHandle(nullptr),
        MAKEINTRESOURCE(IDD_LOG_WINDOW),
        nullptr,
        DlgProc,
        reinterpret_cast<LPARAM>(this));

    if (!m_hWnd)
    {
        return false;
    }

    // コントロールハンドルを取得
    m_hClearButton = GetDlgItem(m_hWnd, IDC_LOG_BTN_CLEAR);
    m_hOpenFolderButton = GetDlgItem(m_hWnd, IDC_LOG_BTN_OPEN_FOLDER);
    m_hLogPathLabel = GetDlgItem(m_hWnd, IDC_LOG_STATIC_PATH);
    m_hListBox = GetDlgItem(m_hWnd, IDC_LOG_LISTBOX);

    // リストボックスのフォント設定
    HFONT hFont = CreateFont(
        16, 0, 0, 0, FW_NORMAL,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        L"Consolas");

    if (m_hListBox)
    {
        SendMessage(m_hListBox, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // 保存されたウィンドウ位置を読み込む
    WindowPositionManager::LoadPosition(m_hWnd, GetRegistryKey());

    return true;
}

void LogWindow::Show()
{
    if (m_hWnd && IsWindow(m_hWnd))
    {
        std::wstring logDir = AppController::GetInstance().GetLogDirectory();
        if (!logDir.empty())
        {
            UpdateLogFilePath(logDir);
        }
        
        ShowWindow(m_hWnd, SW_SHOW);
        SetForegroundWindow(m_hWnd);
        UpdateWindow(m_hWnd);
    }
    else
    {
        Create(nullptr);
        if (m_hWnd)
        {
            std::wstring logDir = AppController::GetInstance().GetLogDirectory();
            if (!logDir.empty())
            {
                UpdateLogFilePath(logDir);
            }
            
            ShowWindow(m_hWnd, SW_SHOW);
            SetForegroundWindow(m_hWnd);
            UpdateWindow(m_hWnd);
        }
    }
}

void LogWindow::Hide()
{
    if (m_hWnd && IsWindow(m_hWnd))
    {
        WindowPositionManager::SavePosition(m_hWnd, GetRegistryKey());
        ShowWindow(m_hWnd, SW_HIDE);
    }
}