#include "framework.h"
#include "NetworkMonitor.h"
#include "NetworkLogger.h"
#include "LogWindow.h"

NetworkMonitor::NetworkMonitor()
    : m_hSession(nullptr)
    , m_lastStatusCode(0)
{
    m_hSession = WinHttpOpen(
        L"NetworkMonitor/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    
    if (m_hSession)
    {
        LogWindow::GetInstance().AddLog(L"WinHTTPセッション初期化成功");
    }
    else
    {
        LogWindow::GetInstance().AddLog(L"エラー: WinHTTPセッション初期化失敗");
    }
}

NetworkMonitor::~NetworkMonitor()
{
    if (m_hSession)
    {
        WinHttpCloseHandle(m_hSession);
    }
}

bool NetworkMonitor::ParseUrl(const std::wstring& url, std::wstring& host, 
                               std::wstring& path, int& port, bool& useHttps)
{
    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);

    WCHAR hostName[256];
    WCHAR urlPath[2048];

    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = _countof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = _countof(urlPath);

    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp))
    {
        return false;
    }

    host = hostName;
    path = urlPath;
    port = urlComp.nPort;
    useHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);

    return true;
}

bool NetworkMonitor::SendHttpRequest(const std::wstring& url, const std::wstring& method)
{
    if (!m_hSession)
    {
        NetworkLogger::GetInstance().LogError(L"Session not initialized", GetLastError());
        LogWindow::GetInstance().AddLog(L"エラー: セッションが初期化されていません");
        return false;
    }

    std::wstring host, path;
    int port;
    bool useHttps;

    if (!ParseUrl(url, host, path, port, useHttps))
    {
        NetworkLogger::GetInstance().LogError(L"Failed to parse URL", GetLastError());
        LogWindow::GetInstance().AddLog(L"エラー: URL解析失敗");
        return false;
    }

    std::wstringstream ss;
    ss << method << L" " << url;
    NetworkLogger::GetInstance().LogRequest(url, method);
    LogWindow::GetInstance().AddLog(ss.str());

    HINTERNET hConnect = WinHttpConnect(m_hSession, host.c_str(), port, 0);
    if (!hConnect)
    {
        NetworkLogger::GetInstance().LogError(L"Failed to connect", GetLastError());
        LogWindow::GetInstance().AddLog(L"エラー: 接続失敗");
        return false;
    }

    DWORD flags = useHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        method.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!hRequest)
    {
        NetworkLogger::GetInstance().LogError(L"Failed to open request", GetLastError());
        LogWindow::GetInstance().AddLog(L"エラー: リクエストオープン失敗");
        WinHttpCloseHandle(hConnect);
        return false;
    }

    BOOL bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    if (bResults)
    {
        bResults = WinHttpReceiveResponse(hRequest, nullptr);
    }

    if (bResults)
    {
        DWORD statusCode = 0;
        DWORD size = sizeof(statusCode);
        WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            nullptr,
            &statusCode,
            &size,
            nullptr);

        m_lastStatusCode = statusCode;
        m_lastResponse.clear();

        DWORD bytesAvailable = 0;
        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0)
        {
            std::vector<char> buffer(bytesAvailable + 1);
            DWORD bytesRead = 0;

            if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead))
            {
                buffer[bytesRead] = '\0';
                m_lastResponse.append(buffer.data(), bytesRead);
            }
        }

        NetworkLogger::GetInstance().LogResponse(statusCode, m_lastResponse, static_cast<DWORD>(m_lastResponse.size()));
        
        std::wstringstream logMsg;
        logMsg << L"レスポンス: " << statusCode << L" (" << m_lastResponse.size() << L" bytes)";
        LogWindow::GetInstance().AddLog(logMsg.str());
    }
    else
    {
        NetworkLogger::GetInstance().LogError(L"Request failed", GetLastError());
        LogWindow::GetInstance().AddLog(L"エラー: リクエスト失敗");
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);

    return bResults != FALSE;
}
