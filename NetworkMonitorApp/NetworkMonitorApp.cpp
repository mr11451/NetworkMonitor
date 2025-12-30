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

// 関数プロトタイプ
INT_PTR CALLBACK MainDlgProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK About(HWND, UINT, WPARAM, LPARAM);

// ヘルパー関数
namespace DialogHelpers
{
    // トグルボタンのテキストを更新
    void UpdateToggleButtonText(HWND hDlg, bool isCapturing)
    {
        HWND hButton = GetDlgItem(hDlg, IDC_BTN_TOGGLE_MONITOR);
        if (hButton)
        {
            int stringId = isCapturing ? IDS_BTN_STOP_CAPTURE : IDS_BTN_START_CAPTURE;
            std::wstring buttonText = UIHelper::LoadStringFromResource(stringId);
            SetWindowTextW(hButton, buttonText.c_str());
        }
    }

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
        
        // 前回使用したIPアドレスを読み込んで設定（デフォルト: localhost）
        std::wstring lastIP = ConfigManager::GetInstance().LoadLastIPAddress();
        UIHelper::SetIPAddressToEditControl(hDlg, IDC_EDIT_TARGET_IP, lastIP);
        
        // ステータステキストを更新
        UIHelper::UpdateStatusText(hDlg, IDC_STATIC_STATUS, 
            AppController::GetInstance().IsCapturing(),
            static_cast<int>(AppController::GetInstance().GetPacketCount()));
        
        // トグルボタンのテキストを初期化
        UpdateToggleButtonText(hDlg, false);
        
        // ログウィンドウを作成（表示はしない）
        LogWindow::GetInstance().Create(hDlg);
        
        // 現在のログディレクトリを表示
        std::wstring logDir = AppController::GetInstance().GetLogDirectory();
        SetDlgItemText(hDlg, IDC_STATIC_LOG_PATH, logDir.c_str());
        
        // 保存されたウィンドウ位置を読み込む
        WindowPositionManager::LoadPosition(hDlg, AppConstants::Registry::MAIN_WINDOW);
        
        return true;
    }
    
    void HandleToggleCapture(HWND hDlg)
    {
        bool isCapturing = AppController::GetInstance().IsCapturing();
        
        if (isCapturing)
        {
            // 監視を停止
            AppController::GetInstance().StopCapture(hDlg);
        }
        else
        {
            // ポート番号を取得
            USHORT port = UIHelper::GetPortFromEditControl(hDlg, IDC_EDIT_PORT_NUMBER);
            if (port == 0)
            {
                return; // ポート番号が無効
            }
            
            // IPアドレスを取得
            std::wstring targetIP = UIHelper::GetIPAddressFromEditControl(hDlg, IDC_EDIT_TARGET_IP);
            
            // localhostを127.0.0.1に解決
            std::wstring resolvedIP = UIHelper::ResolveIPAddress(targetIP);
            
            // 監視を開始（解決されたIPアドレスを渡す）
            AppController::GetInstance().StartCapture(hDlg, port, resolvedIP);
        }
        
        // ボタンテキストを更新
        UpdateToggleButtonText(hDlg, AppController::GetInstance().IsCapturing());
        
        // ステータステキストを更新
        UIHelper::UpdateStatusText(hDlg, IDC_STATIC_STATUS,
            AppController::GetInstance().IsCapturing(),
            static_cast<int>(AppController::GetInstance().GetPacketCount()));
    }
    
    void HandleShowLog()
    {
        LogWindow::GetInstance().Show();
    }
    
    void HandleSelectLogFolder(HWND hDlg)
    {
        // C26815警告を修正: 一時オブジェクトのポインタを使わない
        std::wstring title = UIHelper::LoadStringFromResource(IDS_SELECT_LOG_FOLDER);
        
        BROWSEINFO bi = { 0 };
        bi.hwndOwner = hDlg;
        bi.lpszTitle = title.c_str();
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
                std::wstring msgTemplate = UIHelper::LoadStringFromResource(IDS_LOG_FOLDER_SELECTED);
                swprintf_s(msg, msgTemplate.c_str(), path);
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
        WindowPositionManager::SavePosition(hDlg, AppConstants::Registry::MAIN_WINDOW);
        
        AppController::GetInstance().Cleanup();
        EndDialog(hDlg, IDCANCEL);
        return true;
    }
    
    void HandlePacketCaptured(HWND hDlg)
    {
        UIHelper::UpdateStatusText(hDlg, IDC_STATIC_STATUS,
            AppController::GetInstance().IsCapturing(),
            static_cast<int>(AppController::GetInstance().GetPacketCount()));
    }
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR lpCmdLine,
                     _In_ int nCmdShow)
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
        return DialogHelpers::InitializeDialog(hDlg) ? (INT_PTR)TRUE : (INT_PTR)FALSE;

    case WM_MOVE:
        WindowPositionManager::SavePosition(hDlg, AppConstants::Registry::MAIN_WINDOW);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_BTN_TOGGLE_MONITOR:
            DialogHelpers::HandleToggleCapture(hDlg);
            return (INT_PTR)TRUE;

        case IDC_BTN_SHOW_LOG:
            DialogHelpers::HandleShowLog();
            return (INT_PTR)TRUE;
            
        case IDC_BTN_SELECT_LOG_FOLDER:
            DialogHelpers::HandleSelectLogFolder(hDlg);
            return (INT_PTR)TRUE;

        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hDlg, About);
            return (INT_PTR)TRUE;

        case IDCANCEL:
            if (DialogHelpers::HandleCloseDialog(hDlg))
            {
                return (INT_PTR)TRUE;
            }
            return (INT_PTR)FALSE;

        default:
            return (INT_PTR)FALSE;
        }

    case AppConstants::WM_PACKET_CAPTURED:
        DialogHelpers::HandlePacketCaptured(hDlg);
        return (INT_PTR)TRUE;

    case WM_CLOSE:
        PostMessage(hDlg, WM_COMMAND, IDCANCEL, 0);
        return (INT_PTR)TRUE;

    default:
        return (INT_PTR)FALSE;
    }
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
