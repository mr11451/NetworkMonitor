#include "framework.h"
#include "NetworkLogger.h"
#include "LogWindow.h"
#include <sstream>
#include <iomanip>
#include <mutex> // 既にインクルード済みであれば不要

// Singleton instance getter
NetworkLogger& NetworkLogger::GetInstance()
{
    static NetworkLogger instance;
    return instance;
}

NetworkLogger::NetworkLogger()
    : m_isLogging(false)
    , m_logFilePath(L"")
{
}

NetworkLogger::~NetworkLogger()
{
    StopLogging();
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

bool NetworkLogger::StartLogging(const std::wstring& filePath)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_isLogging)
    {
        return false;
    }
    
    m_logFilePath = filePath;
    m_logFile.open(filePath, std::ios::out | std::ios::app);
    
    if (!m_logFile.is_open())
    {
        return false;
    }
    
    m_isLogging = true;
    
    // ログ開始のヘッダーを書き込む
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    m_logFile << L"\n=== Logging Started ===" << std::endl;
    m_logFile << FormatTimestamp(st) << L" : Log session started" << std::endl;
    m_logFile.flush();
    
    return true;
}

void NetworkLogger::StopLogging()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_isLogging && m_logFile.is_open())
    {
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        m_logFile << FormatTimestamp(st) << L" : Log session ended" << std::endl;
        m_logFile << L"=== Logging Stopped ===" << std::endl;
        m_logFile.close();
        
        m_isLogging = false;
    }
}

void NetworkLogger::LogRequest(const std::wstring& message, const std::wstring& requestType)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_isLogging || !m_logFile.is_open())
    {
        return;
    }
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    m_logFile << FormatTimestamp(st) 
              << L" [" << requestType << L"] " 
              << message << std::endl;
    m_logFile.flush();
}

void NetworkLogger::LogResponse(unsigned long statusCode, const std::string& response, unsigned long size)
{
    std::wstringstream ss;
    ss << L"HTTP Response - Status: " << statusCode 
       << L", Size: " << size << L" bytes";
    
    LogWindow::GetInstance().AddLogThreadSafe(ss.str());
}

void NetworkLogger::LogError(const std::wstring& errorMessage, unsigned long errorCode)
{
    std::wstringstream ss;
    ss << L"Error: " << errorMessage << L" (Code: " << errorCode << L")";
    
    LogWindow::GetInstance().AddLogThreadSafe(ss.str());
}

// int版のLogErrorオーバーロード（PacketCaptureクラスからの呼び出し用）
void NetworkLogger::LogError(const std::wstring& errorMessage, int errorCode)
{
    LogError(errorMessage, static_cast<unsigned long>(errorCode));
}

std::wstring NetworkLogger::FormatTimestamp(const SYSTEMTIME& st) const
{
    std::wostringstream oss;
    oss << std::setfill(L'0')
        << std::setw(4) << st.wYear << L"-"
        << std::setw(2) << st.wMonth << L"-"
        << std::setw(2) << st.wDay << L" "
        << std::setw(2) << st.wHour << L":"
        << std::setw(2) << st.wMinute << L":"
        << std::setw(2) << st.wSecond << L"."
        << std::setw(3) << st.wMilliseconds;
    return oss.str();
}

bool NetworkLogger::IsLogging() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_isLogging;
}