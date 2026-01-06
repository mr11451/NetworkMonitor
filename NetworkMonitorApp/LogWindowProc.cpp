#include "framework.h"
#include "LogWindow.h"
#include "resource.h"
#include "WindowPositionManager.h"
#include <shellapi.h>

INT_PTR CALLBACK LogWindow::DlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    LogWindow* pThis = nullptr;

    if (message == WM_INITDIALOG)
    {
        pThis = reinterpret_cast<LogWindow*>(lParam);
        SetWindowLongPtr(hDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));

        // --- リソースで管理されたコントロールのハンドル取得 ---
        pThis->m_hListBox = GetDlgItem(hDlg, IDC_LOG_LISTBOX);
        pThis->m_hWnd = hDlg;
        // ------------------------------------------------------

        return (INT_PTR)TRUE;
    }
    else
    {
        pThis = reinterpret_cast<LogWindow*>(GetWindowLongPtr(hDlg, GWLP_USERDATA));
    }

    if (pThis)
    {
        switch (message)
        {
        case WM_ADD_LOG:
        {
            std::wstring* pMessage = reinterpret_cast<std::wstring*>(lParam);
            if (pMessage)
            {
                pThis->AddLog(*pMessage);
                delete pMessage;
            }
            return (INT_PTR)TRUE;
        }

        case WM_SIZE:
        {
            RECT rc;
            GetClientRect(hDlg, &rc);

            // マージンを定義
            const int margin = 10;
            const int boxtop = 40;

            // リストボックスをウィンドウ全体に広げる（マージン分だけ内側に）
            if (pThis->m_hListBox && IsWindow(pThis->m_hListBox))
            {
                SetWindowPos(
                    pThis->m_hListBox,
                    nullptr,
                    margin,
                    rc.top + boxtop + 2 * margin,
                    rc.right - 2 * margin,
                    rc.bottom - boxtop - 3 * margin,
                    SWP_NOZORDER
                );
            }
            return (INT_PTR)TRUE;
        }
        
        case WM_MOVE:
        {
            WindowPositionManager::SavePosition(hDlg, pThis->GetRegistryKey());
            return (INT_PTR)TRUE;
        }

        case WM_COMMAND:
        {
            switch (LOWORD(wParam))
            {
            case IDC_LOG_BTN_CLEAR:
                pThis->Clear();
                return (INT_PTR)TRUE;
                
            case IDC_LOG_BTN_OPEN_FOLDER:
            {
                std::wstring logPath;
                {
                    std::lock_guard<std::mutex> lock(pThis->m_mutex);
                    logPath = pThis->m_logFilePath;
                }
                
                if (!logPath.empty())
                {
                    ShellExecuteW(nullptr, L"open", logPath.c_str(), nullptr, nullptr, SW_SHOW);
                }
                else
                {
                    MessageBoxW(hDlg, 
                        pThis->LoadStringFromResource(IDS_LOG_ERROR_PATH_NOT_SET).c_str(), 
                        pThis->LoadStringFromResource(IDS_INFO_TITLE).c_str(), 
                        MB_OK | MB_ICONINFORMATION);
                }
                return (INT_PTR)TRUE;
            }
            }
            break;
        }

        case WM_CLOSE:
        {
            pThis->Hide();
            return (INT_PTR)TRUE;
        }

        case WM_DESTROY:
        {
            pThis->m_hWnd = nullptr;
            pThis->m_hListBox = nullptr;
            pThis->m_hClearButton = nullptr;
            pThis->m_hLogPathLabel = nullptr;
            pThis->m_hOpenFolderButton = nullptr;
            return (INT_PTR)TRUE;
        }
        }
    }

    return (INT_PTR)FALSE;
}