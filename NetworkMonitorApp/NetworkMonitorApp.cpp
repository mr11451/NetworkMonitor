// NetworkMonitorApp.cpp : アプリケーションのエントリ ポイントを定義します。
//

#include "framework.h"
#include "NetworkMonitorApp.h"
#include "AppConstants.h"
#include "AppController.h"
#include "UIHelper.h"
#include "ConfigManager.h"
#include "LogWindow.h"
#include "WindowPositionManager.h"
#include "Resource.h"
#include <shlobj.h>

// グローバル変数
HINSTANCE hInst;

// レジストリキー定数
namespace RegistryKeys
{
    constexpr const wchar_t* MAIN_WINDOW = L"Software\\NetworkMonitor\\MainWindow";
}

// 関数プロトタイプ
INT_PTR CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK About(HWND, UINT, WPARAM, LPARAM);

// ヘルパー関数
namespace
{
    bool InitializeDialog(HWND hDlg)
    {
        // アプリケーションコントローラーを初期化
        if (!AppController::GetInstance().Initialize(hDlg))
        {
            return false;
        }
        
        // 前回使用したポート番号を読み込んで設定
        USHORT lastPort = ConfigManager::GetInstance().LoadLastPort();
        UIHelper::SetPortToEditControl(hDlg, IDC_EDIT_PORT_NUMBER, lastPort);
        
        // ステータステキストを更新
        UIHelper::UpdateStatusText(hDlg, IDC_STATIC_STATUS, 
            AppController::GetInstance().IsCapturing(),
            AppController::GetInstance().GetPacketCount());
        
        // ログウィンドウを作成（表示はしない）
        LogWindow::GetInstance().Create(hDlg);
        
        // 現在のログディレクトリを表示
        std::wstring logDir = AppController::GetInstance().GetLogDirectory();
        SetDlgItemText(hDlg, IDC_STATIC_LOG_PATH, logDir.c_str());
        
        // 保存されたウィンドウ位置を読み込む
        WindowPositionManager::LoadPosition(hDlg, RegistryKeys::MAIN_WINDOW);
        
        return true;
    }
    
    void HandleStartCapture(HWND hDlg)
    {
        USHORT port = UIHelper::GetPortFromEditControl(hDlg, IDC_EDIT_PORT_NUMBER);
        if (port > 0)
        {
            AppController::GetInstance().StartCapture(hDlg, port);
            UIHelper::UpdateStatusText(hDlg, IDC_STATIC_STATUS,
                AppController::GetInstance().IsCapturing(),
                AppController::GetInstance().GetPacketCount());
        }
    }
    
    void HandleStopCapture(HWND hDlg)
    {
        AppController::GetInstance().StopCapture(hDlg);
        UIHelper::UpdateStatusText(hDlg, IDC_STATIC_STATUS,
            AppController::GetInstance().IsCapturing(),
            AppController::GetInstance().GetPacketCount());
    }
    
    void HandleShowLog()
    {
        LogWindow::GetInstance().Show();
    }
    
    void HandleSelectLogFolder(HWND hDlg)
    {
        BROWSEINFO bi = { 0 };
        bi.hwndOwner = hDlg;
        bi.lpszTitle = UIHelper::LoadStringFromResource(IDS_SELECT_LOG_FOLDER).c_str();
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
        
        LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
        if (pidl != nullptr)
        {
            WCHAR path[MAX_PATH];
            if (SHGetPathFromIDList(pidl, path))
            {
                AppController::GetInstance().SetLogDirectory(path);
                SetDlgItemText(hDlg, IDC_STATIC_LOG_PATH, path);
                
                WCHAR msg[512];
                swprintf_s(msg, 
                    UIHelper::LoadStringFromResource(IDS_LOG_FOLDER_SELECTED).c_str(), 
                    path);
                UIHelper::ShowInfoMessage(hDlg, msg, IDS_INFO_TITLE);
            }
            
            CoTaskMemFree(pidl);
        }
    }
    
    bool HandleCloseDialog(HWND hDlg)
    {
        if (AppController::GetInstance().IsCapturing())
        {
            if (!UIHelper::ShowConfirmDialog(hDlg, IDS_CONFIRM_EXIT, IDS_CONFIRM_TITLE))
            {
                return false;
            }
        }
        
        // ウィンドウ位置を保存
        WindowPositionManager::SavePosition(hDlg, RegistryKeys::MAIN_WINDOW);
        
        AppController::GetInstance().Cleanup();
        EndDialog(hDlg, IDCANCEL);
        return true;
    }
    
    void HandlePacketCaptured(HWND hDlg)
    {
        UIHelper::UpdateStatusText(hDlg, IDC_STATIC_STATUS,
            AppController::GetInstance().IsCapturing(),
            AppController::GetInstance().GetPacketCount());
    }
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    hInst = hInstance;

    // メインダイアログを表示
    DialogBoxW(hInstance, MAKEINTRESOURCE(IDD_MAIN_DIALOG), nullptr, MainDlgProc);

    return 0;
}

INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
        return InitializeDialog(hDlg) ? (INT_PTR)TRUE : (INT_PTR)FALSE;

    case WM_MOVE:
        WindowPositionManager::SavePosition(hDlg, RegistryKeys::MAIN_WINDOW);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_BTN_START_CUSTOM:
            HandleStartCapture(hDlg);
            break;

        case IDC_BTN_STOP_CAPTURE:
            HandleStopCapture(hDlg);
            break;

        case IDC_BTN_SHOW_LOG:
            HandleShowLog();
            break;
            
        case IDC_BTN_SELECT_LOG_FOLDER:
            HandleSelectLogFolder(hDlg);
            break;

        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hDlg, About);
            break;

        case IDCANCEL:
            if (HandleCloseDialog(hDlg))
            {
                return (INT_PTR)TRUE;
            }
            break;

        default:
            return (INT_PTR)FALSE;
        }
        break;
    }

    case AppConstants::WM_PACKET_CAPTURED:
        HandlePacketCaptured(hDlg);
        break;

    case WM_CLOSE:
        PostMessage(hDlg, WM_COMMAND, IDCANCEL, 0);
        return (INT_PTR)TRUE;

    default:
        return (INT_PTR)FALSE;
    }
    
    return (INT_PTR)TRUE;
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
