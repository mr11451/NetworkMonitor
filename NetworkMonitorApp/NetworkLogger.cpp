#include "framework.h"
#include "NetworkLogger.h"
#include <chrono>
#include <shlobj.h>

NetworkLogger& NetworkLogger::GetInstance()
{
    static NetworkLogger instance;
    return instance;
}

NetworkLogger::NetworkLogger()
{
    // バイナリログと同じディレクトリを使用
    std::wstring logDir = GetDefaultLogDirectory();
    
    // タイムスタンプ付きのファイル名を生成
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    WCHAR fileName[MAX_PATH];
    swprintf_s(fileName, L"\\TextLog_%04d%02d%02d_%02d%02d%02d.txt",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    
    m_logFilePath = logDir + fileName;
}

NetworkLogger::~NetworkLogger()
{
}

std::wstring NetworkLogger::GetDefaultLogDirectory() const
{
    WCHAR documentsPath[MAX_PATH];
    
    // ドキュメントフォルダを取得
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, 0, documentsPath)))
    {
        std::wstring logPath = documentsPath;
        logPath += L"\\NetworkMonitor";
        
        // ディレクトリが存在しない場合は作成
        CreateDirectoryW(logPath.c_str(), nullptr);
        
        return logPath;
    }
    
    // フォールバック: TEMPフォルダ
    WCHAR tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    return tempPath;
}

void NetworkLogger::SetLogFilePath(const std::wstring& filePath)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logFilePath = filePath;
}

std::wstring NetworkLogger::GetLogFilePath() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_logFilePath;
}

std::wstring NetworkLogger::GetTimestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm localTime;
    localtime_s(&localTime, &time);

    std::wstringstream ss;
    ss << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S")
       << L"." << std::setfill(L'0') << std::setw(3) << ms.count();
    return ss.str();
}

void NetworkLogger::WriteLog(const std::wstring& message)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    std::wofstream logFile(m_logFilePath, std::ios::app);
    if (logFile.is_open())
    {
        logFile << message << std::endl;
        logFile.close();
    }
}

void NetworkLogger::LogRequest(const std::wstring& url, const std::wstring& method)
{
    std::wstringstream ss;
    ss << L"[" << GetTimestamp() << L"] REQUEST - Method: " << method
       << L", URL: " << url;
    WriteLog(ss.str());
}

void NetworkLogger::LogResponse(DWORD statusCode, const std::string& responseData, DWORD dataSize)
{
    std::wstringstream ss;
    ss << L"[" << GetTimestamp() << L"] RESPONSE - Status: " << statusCode
       << L", Size: " << dataSize << L" bytes";
    WriteLog(ss.str());

    if (dataSize > 0 && dataSize < 1024)
    {
        std::wstring wResponseData(responseData.begin(), responseData.end());
        ss.str(L"");
        ss << L"[" << GetTimestamp() << L"] DATA - " << wResponseData;
        WriteLog(ss.str());
    }
}

void NetworkLogger::LogError(const std::wstring& errorMessage, DWORD errorCode)
{
    std::wstringstream ss;
    ss << L"[" << GetTimestamp() << L"] ERROR - " << errorMessage
       << L" (Code: " << errorCode << L")";
    WriteLog(ss.str());
}