#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>

#pragma comment(lib, "winhttp.lib")

class NetworkLogger
{
public:
    static NetworkLogger& GetInstance();
    
    void LogRequest(const std::wstring& url, const std::wstring& method);
    void LogResponse(DWORD statusCode, const std::string& responseData, DWORD dataSize);
    void LogError(const std::wstring& errorMessage, DWORD errorCode);
    void SetLogFilePath(const std::wstring& filePath);
    std::wstring GetLogFilePath() const; // 追加: ログファイルパスを取得

private:
    NetworkLogger();
    ~NetworkLogger();
    NetworkLogger(const NetworkLogger&) = delete;
    NetworkLogger& operator=(const NetworkLogger&) = delete;

    std::wstring GetTimestamp();
    void WriteLog(const std::wstring& message);
    std::wstring GetDefaultLogDirectory() const; // 追加: デフォルトのログディレクトリを取得

    std::wstring m_logFilePath;
    mutable std::mutex m_mutex; // constメンバー関数でも使用できるようにmutable化
};