#pragma once
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

class NetworkMonitor
{
public:
    NetworkMonitor();
    ~NetworkMonitor();

    bool SendHttpRequest(const std::wstring& url, const std::wstring& method = L"GET");
    std::string GetLastResponse() const { return m_lastResponse; }
    DWORD GetLastStatusCode() const { return m_lastStatusCode; }

private:
    bool ParseUrl(const std::wstring& url, std::wstring& host, std::wstring& path, int& port, bool& useHttps);
    
    HINTERNET m_hSession;
    std::string m_lastResponse;
    DWORD m_lastStatusCode;
};