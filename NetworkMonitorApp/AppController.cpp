#include "framework.h"
#include "AppController.h"
#include "AppConstants.h"
#include "UIHelper.h"
#include "ConfigManager.h"
#include "BinaryLogger.h"
#include "LogWindow.h"
#include "Resource.h"
#include <shlobj.h>
#include <Shlwapi.h>
#include <sstream>
#include <mutex>
#include <iomanip>  // 追加: std::setw, std::setfill のために必要
#include <shellapi.h> // 追加: ShellExecuteWのために必要
#pragma comment(lib, "Shlwapi.lib")

AppController& AppController::GetInstance()
{
    static AppController instance;
    return instance;
}

bool AppController::Initialize(HWND hMainDlg)
{
    if (!hMainDlg)
    {
        return false;
    }
    
    m_hMainDlg = hMainDlg;
    m_packetCount = 0;
    
    // ログフォルダパスを読み込み
    LoadLogFolderPath();
    
    try
    {
        m_pNetworkMonitor = std::make_unique<NetworkMonitor>();
        m_pPacketCapture = std::make_unique<PacketCapture>();

        // パケットキャプチャのコールバックを設定
        m_pPacketCapture->SetPacketCallback(
            [this](const PacketInfo& packet) {
                OnPacketCaptured(packet);
            }
        );
        
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void AppController::Cleanup()
{
    StopBinaryLogging();
    StopTextLogging(); // 追加
    
    if (m_pPacketCapture && m_pPacketCapture->IsCapturing())
    {
        m_pPacketCapture->StopCapture();
    }
    m_pPacketCapture.reset();
    m_pNetworkMonitor.reset();
    m_hMainDlg = nullptr;
    m_packetCount = 0;
}

bool AppController::StartCapture(HWND hDlg, USHORT port)
{
    if (port == 0)
    {
        return false;
    }

    if (!m_pPacketCapture)
    {
        UIHelper::ShowErrorMessage(hDlg, IDS_ERROR_CAPTURE_FAILED, IDS_ERROR_TITLE);
        return false;
    }

    if (m_pPacketCapture->IsCapturing())
    {
        UIHelper::ShowErrorMessage(hDlg, IDS_ERROR_ALREADY_CAPTURING, IDS_INFO_TITLE);
        return false;
    }

    m_packetCount = 0;
    
    // バイナリログとテキストログを自動開始
    if (!IsBinaryLogging())
    {
        StartBinaryLogging(hDlg, GetDefaultBinaryLogPath());
    }
    
    if (!IsTextLogging()) // 追加
    {
        StartTextLogging(hDlg, GetDefaultTextLogPath());
    }
    
    if (m_pPacketCapture->StartCapture(port))
    {
        // ポート番号を保存
        ConfigManager::GetInstance().SaveLastPort(port);
        
        WCHAR msg[AppConstants::MAX_STRING_LENGTH];
        swprintf_s(msg, AppConstants::MAX_STRING_LENGTH, 
            UIHelper::LoadStringFromResource(IDS_INFO_CAPTURE_STARTED).c_str(), 
            port);
        UIHelper::ShowInfoMessage(hDlg, msg, IDS_INFO_TITLE);
        InvalidateRect(hDlg, nullptr, TRUE);
        return true;
    }
    else
    {
        StopBinaryLogging();
        StopTextLogging(); // 追加
        UIHelper::ShowErrorMessage(hDlg, IDS_ERROR_CAPTURE_FAILED, IDS_ERROR_TITLE);
        return false;
    }
}

void AppController::StopCapture(HWND hDlg)
{
    if (m_pPacketCapture && m_pPacketCapture->IsCapturing())
    {
        m_pPacketCapture->StopCapture();
        StopBinaryLogging();
        StopTextLogging(); // 追加
        
        UIHelper::ShowInfoMessage(hDlg,
            UIHelper::LoadStringFromResource(IDS_INFO_CAPTURE_STOPPED),
            IDS_INFO_TITLE);
        InvalidateRect(hDlg, nullptr, TRUE);
    }
}

bool AppController::StartBinaryLogging(HWND hDlg, const std::wstring& filePath)
{
    return BinaryLogger::GetInstance().StartLogging(filePath);
}

void AppController::StopBinaryLogging()
{
    BinaryLogger::GetInstance().StopLogging();
}

bool AppController::IsBinaryLogging() const
{
    return BinaryLogger::GetInstance().IsLogging();
}

// テキストログ用メソッドの実装
bool AppController::StartTextLogging(HWND hDlg, const std::wstring& filePath)
{
    std::lock_guard<std::mutex> lock(m_textLogMutex);
    
    if (m_isTextLogging)
    {
        return false; // 既にログ中
    }
    
    m_textLogFilePath = filePath;
    m_isTextLogging = true;
    
    // ヘッダーを書き込み
    std::wofstream logFile(filePath, std::ios::out | std::ios::trunc);
    if (!logFile.is_open())
    {
        m_isTextLogging = false;
        return false;
    }
    
    logFile << L"=== Network Monitor Log ===" << std::endl;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    logFile << L"Start Time: " 
            << st.wYear << L"/" 
            << std::setfill(L'0') << std::setw(2) << st.wMonth << L"/" 
            << std::setw(2) << st.wDay << L" "
            << std::setw(2) << st.wHour << L":"
            << std::setw(2) << st.wMinute << L":"
            << std::setw(2) << st.wSecond << std::endl;
    logFile << L"============================" << std::endl << std::endl;
    logFile.close(); // ファイルを閉じる
    
    return true;
}

void AppController::StopTextLogging()
{
    std::lock_guard<std::mutex> lock(m_textLogMutex);
    
    if (m_isTextLogging)
    {
        // フッターを書き込み
        std::wofstream logFile(m_textLogFilePath, std::ios::out | std::ios::app);
        if (logFile.is_open())
        {
            SYSTEMTIME st;
            GetLocalTime(&st);
            logFile << std::endl << L"============================" << std::endl;
            logFile << L"End Time: " 
                    << st.wYear << L"/" 
                    << std::setfill(L'0') << std::setw(2) << st.wMonth << L"/" 
                    << std::setw(2) << st.wDay << L" "
                    << std::setw(2) << st.wHour << L":"
                    << std::setw(2) << st.wMinute << L":"
                    << std::setw(2) << st.wSecond << std::endl;
            logFile.close(); // ファイルを閉じる
        }
        
        m_isTextLogging = false;
        m_textLogFilePath.clear();
    }
}

bool AppController::IsTextLogging() const
{
    return m_isTextLogging;
}

void AppController::WriteTextLog(const std::wstring& logText)
{
    std::lock_guard<std::mutex> lock(m_textLogMutex);
    
    if (m_isTextLogging && !m_textLogFilePath.empty())
    {
        // ファイルを開く（追記モード）
        std::wofstream logFile(m_textLogFilePath, std::ios::out | std::ios::app);
        if (logFile.is_open())
        {
            // タイムスタンプを追加
            SYSTEMTIME st;
            GetLocalTime(&st);
            
            logFile << L"[" 
                    << std::setfill(L'0') << std::setw(2) << st.wHour << L":"
                    << std::setw(2) << st.wMinute << L":"
                    << std::setw(2) << st.wSecond << L"."
                    << std::setw(3) << st.wMilliseconds << L"] "
                    << logText << std::endl;
            logFile.close(); // ファイルを閉じる
        }
    }
}

bool AppController::IsCapturing() const
{
    return m_pPacketCapture && m_pPacketCapture->IsCapturing();
}

void AppController::IncrementPacketCount()
{
    ++m_packetCount;
}

void AppController::SetLogDirectory(const std::wstring& directory)
{
    m_logDirectory = directory;
    SaveLogFolderPath(directory);
}

std::wstring AppController::GetLogDirectory() const
{
    if (!m_logFolderPath.empty())
    {
        return m_logFolderPath;
    }
    
    if (!m_logDirectory.empty())
    {
        return m_logDirectory;
    }
    
    return GetDefaultLogFolderPath();
}

std::wstring AppController::GetDefaultBinaryLogPath() const
{
    std::wstring logDir = GetLogDirectory();
    
    // ディレクトリが存在しない場合は作成
    DWORD attrib = GetFileAttributesW(logDir.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES)
    {
        CreateDirectoryW(logDir.c_str(), nullptr);
    }
    
    return logDir; // ディレクトリパスを返す
}

// テキストログのデフォルトパスを生成
std::wstring AppController::GetDefaultTextLogPath() const
{
    std::wstring logDir = GetLogDirectory();
    
    if (!PathFileExistsW(logDir.c_str()))
    {
        CreateDirectoryW(logDir.c_str(), nullptr);
    }
    
    // タイムスタンプを取得
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // ベースファイル名（日付_時刻）
    WCHAR baseFileName[MAX_PATH];
    swprintf_s(baseFileName, L"Capture_%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    
    // 通し番号を000から付けてユニークなファイル名を探す
    int sequenceNumber = 0;
    std::wstring fullPath;
    
    do
    {
        WCHAR fileName[MAX_PATH];
        swprintf_s(fileName, L"%s_%03d.txt", baseFileName, sequenceNumber);
        
        fullPath = logDir + L"\\" + fileName;
        sequenceNumber++;
        
        if (sequenceNumber > 999)
        {
            break;
        }
        
    } while (PathFileExistsW(fullPath.c_str()));
    
    return fullPath;
}

std::wstring AppController::GenerateUniqueLogFileName(const std::wstring& directory) const
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    WCHAR baseFileName[MAX_PATH];
    swprintf_s(baseFileName, L"Capture_%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    
    int sequenceNumber = 0;
    std::wstring fullPath;
    
    do
    {
        WCHAR fileName[MAX_PATH];
        swprintf_s(fileName, L"%s_%03d.netlog", baseFileName, sequenceNumber);
        
        fullPath = directory + L"\\" + fileName;
        sequenceNumber++;
        
        if (sequenceNumber > 999)
        {
            break;
        }
        
    } while (PathFileExistsW(fullPath.c_str()));
    
    return fullPath;
}

void AppController::OnPacketCaptured(const PacketInfo& packet)
{
    IncrementPacketCount();
    
    // バイナリログに記録
    if (IsBinaryLogging())
    {
        BinaryLogger::GetInstance().LogPacket(packet);
    }
    
    // ログウィンドウに表示用のテキストを追加（ヘッダー情報）
    std::wstring logText = L"[" + 
        std::wstring(packet.protocol.begin(), packet.protocol.end()) + L"] " +
        std::wstring(packet.sourceIP.begin(), packet.sourceIP.end()) + L":" + 
        std::to_wstring(packet.sourcePort) + L" -> " +
        std::wstring(packet.destIP.begin(), packet.destIP.end()) + L":" + 
        std::to_wstring(packet.destPort) + L" (" + 
        std::to_wstring(packet.dataSize) + L" bytes)";
    
    // パケットデータを16進数ダンプ形式で追加
    if (!packet.data.empty())
    {
        logText += L"\n  Data: ";
        
        // 最初の64バイトまたはデータ全体を表示
        size_t displaySize = (std::min)(packet.data.size(), static_cast<size_t>(64));
        
        for (size_t i = 0; i < displaySize; ++i)
        {
            WCHAR hex[4];
            swprintf_s(hex, L"%02X ", packet.data[i]);
            logText += hex;
            
            // 16バイトごとに改行
            if ((i + 1) % 16 == 0 && i + 1 < displaySize)
            {
                logText += L"\n        ";
            }
        }
        
        // データが64バイトより多い場合は省略を示す
        if (packet.data.size() > displaySize)
        {
            logText += L"... (" + std::to_wstring(packet.data.size() - displaySize) + L" more bytes)";
        }
        
        // ASCII表示も追加（オプション）
        logText += L"\n  ASCII: ";
        for (size_t i = 0; i < displaySize; ++i)
        {
            BYTE b = packet.data[i];
            // 印字可能文字のみ表示、それ以外は'.'
            logText += (b >= 32 && b < 127) ? static_cast<wchar_t>(b) : L'.';
            
            // 16文字ごとにスペース
            if ((i + 1) % 16 == 0 && i + 1 < displaySize)
            {
                logText += L"\n         ";
            }
        }
    }
    
    // テキストログに書き込み
    if (IsTextLogging())
    {
        WriteTextLog(logText);
    }
    
    LogWindow::GetInstance().AddLogThreadSafe(logText);
    
    if (m_hMainDlg)
    {
        PostMessage(m_hMainDlg, AppConstants::WM_PACKET_CAPTURED, 0, 0);
    }
}

std::wstring AppController::GetDefaultLogFolderPath() const
{
    WCHAR path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) 
    {
        std::wstring appDataPath = path;
        appDataPath += L"\\NetworkMonitor";
        
        if (!PathFileExistsW(appDataPath.c_str())) 
        {
            CreateDirectoryW(appDataPath.c_str(), NULL);
        }
        return appDataPath;
    }
    return L"";;
}

void AppController::LoadLogFolderPath() 
{
    HKEY hKey;
    const wchar_t* subKey = L"Software\\NetworkMonitor";
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) 
    {
        WCHAR buffer[MAX_PATH];
        DWORD bufferSize = sizeof(buffer);
        DWORD type = REG_SZ;
        
        if (RegQueryValueExW(hKey, L"LogFolderPath", NULL, &type, 
                            (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) 
        {
            m_logFolderPath = buffer;
        }
        RegCloseKey(hKey);
    }
    
    if (m_logFolderPath.empty() || !PathFileExistsW(m_logFolderPath.c_str())) 
    {
        m_logFolderPath = GetDefaultLogFolderPath();
        SaveLogFolderPath(m_logFolderPath);
    }
    
    if (m_hMainDlg) 
    {
        SetDlgItemTextW(m_hMainDlg, IDC_STATIC_LOG_PATH, m_logFolderPath.c_str());
    }
}

void AppController::SaveLogFolderPath(const std::wstring& path) 
{
    HKEY hKey;
    const wchar_t* subKey = L"Software\\NetworkMonitor";
    
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subKey, 0, NULL, 
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) 
    {
        RegSetValueExW(hKey, L"LogFolderPath", 0, REG_SZ, 
                      (const BYTE*)path.c_str(), 
                      (DWORD)((path.length() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    
    m_logFolderPath = path;
    
    if (m_hMainDlg) 
    {
        SetDlgItemTextW(m_hMainDlg, IDC_STATIC_LOG_PATH, m_logFolderPath.c_str());
    }
}

void AppController::OnSelectLogFolder(HWND hDlg) 
{
    BROWSEINFOW bi = { 0 };
    bi.hwndOwner = hDlg;
    bi.lpszTitle = L"ログの保存先フォルダを選択してください";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    
    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl != NULL) 
    {
        WCHAR selectedPath[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, selectedPath)) 
        {
            SaveLogFolderPath(selectedPath);
            
            WCHAR message[MAX_PATH + 100];
            swprintf_s(message, L"ログ保存先を変更しました:\n%s\n\n次回の監視開始から、このフォルダにログが保存されます。", selectedPath);
            MessageBoxW(hDlg, message, L"通知", MB_OK | MB_ICONINFORMATION);
        }
        CoTaskMemFree(pidl);
    }
}

void AppController::OpenSaveLocation(HWND hDlg)
{
    // BinaryLoggerからディレクトリを取得
    std::wstring logDir = BinaryLogger::GetInstance().GetLogDirectory();
    
    if (logDir.empty())
    {
        // ログが記録されていない場合は、設定されているログディレクトリを使用
        logDir = GetLogDirectory();
    }
    
    // パスが存在するか確認
    DWORD attrib = GetFileAttributesW(logDir.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES)
    {
        // ディレクトリが存在しない場合は作成を試みる
        if (CreateDirectoryW(logDir.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
        {
            attrib = GetFileAttributesW(logDir.c_str());
        }
        else
        {
            WCHAR msg[512];
            swprintf_s(msg, L"ログ保存先が見つかりません:\n%s\n\nディレクトリの作成に失敗しました。", 
                       logDir.c_str());
            MessageBoxW(hDlg, msg, L"エラー", MB_OK | MB_ICONERROR);
            return;
        }
    }
    
    // エクスプローラーでディレクトリを開く
    ShellExecuteW(NULL, L"explore", logDir.c_str(), NULL, NULL, SW_SHOW);
}
