#include "framework.h"
#define NOMINMAX
#include "PacketCapture.h"
#include "NetworkLogger.h"
#include "LogWindow.h"
#include "UIHelper.h"
#include "Resource.h"
#include <sstream>
#include <iomanip>

// 定数定義
namespace
{
    constexpr int RECV_BUFFER_SIZE = 65536;     // 64KB
    constexpr int SOCKET_BUFFER_SIZE = 256 * 1024; // 256KB
    constexpr DWORD RECV_TIMEOUT_MS = 5000;     // 5秒
    constexpr int MAX_RETRY_COUNT = 999;
}

PacketCapture::PacketCapture()
    : m_socket(INVALID_SOCKET)
    , m_socketIPv6(INVALID_SOCKET)
    , m_loopbackSocket(INVALID_SOCKET)
    , m_targetPort(0)
    , m_isCapturing(false)
{
    if (!InitializeWinsock())
    {
        LogWindow::GetInstance().AddLog(
            UIHelper::LoadStringFromResource(IDS_ERROR_WSASTARTUP_FAILED));
    }
}

PacketCapture::~PacketCapture()
{
    StopCapture();
    WSACleanup();
}

bool PacketCapture::InitializeWinsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        NetworkLogger::GetInstance().LogError(L"WSAStartup failed", result);
        return false;
    }
    return true;
}

void PacketCapture::SetPacketCallback(std::function<void(const PacketInfo&)> callback)
{
    m_callback = callback;
}

bool PacketCapture::InitializeRawSocket()
{
    // RAWソケット作成
    if (!CreateRawSocket())
    {
        return false;
    }

    // ローカルIPアドレスを取得してバインド
    sockaddr_in bindAddr;
    if (!GetLocalAddressAndBind(bindAddr))
    {
        return false;
    }

    // ソケットオプション設定
    if (!ConfigureSocketOptions())
    {
        return false;
    }

    // プロミスキャスモード有効化
    if (!EnablePromiscuousMode())
    {
        return false;
    }

    // 初期化成功メッセージ
    LogInitializationSuccess(bindAddr);
    return true;
}

bool PacketCapture::InitializeLoopbackSocket()
{
    // ループバック用RAWソケット作成
    m_loopbackSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (m_loopbackSocket == INVALID_SOCKET)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to create loopback socket", error);
        return false;
    }

    // ループバックアドレスにバインド
    sockaddr_in loopbackAddr = { 0 };
    loopbackAddr.sin_family = AF_INET;
    loopbackAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    loopbackAddr.sin_port = 0;

    if (bind(m_loopbackSocket, reinterpret_cast<sockaddr*>(&loopbackAddr), 
             sizeof(loopbackAddr)) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to bind loopback socket", error);
        closesocket(m_loopbackSocket);
        m_loopbackSocket = INVALID_SOCKET;
        return false;
    }

    // プロミスキャスモード有効化
    DWORD flag = RCVALL_ON;
    if (ioctlsocket(m_loopbackSocket, SIO_RCVALL, &flag) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to set loopback promiscuous mode", error);
        closesocket(m_loopbackSocket);
        m_loopbackSocket = INVALID_SOCKET;
        return false;
    }

    WCHAR msg[256];
    swprintf_s(msg, L"Loopback socket initialized on 127.0.0.1");
    LogWindow::GetInstance().AddLog(msg);

    return true;
}

bool PacketCapture::InitializeRawSocketIPv6()
{
    // IPv6 RAWソケット作成
    if (!CreateRawSocketIPv6())
    {
        return false;
    }

    // ローカルIPv6アドレスを取得してバインド
    sockaddr_in6 bindAddr;
    if (!GetLocalAddressAndBindIPv6(bindAddr))
    {
        return false;
    }

    // プロミスキャスモード有効化
    if (!EnablePromiscuousModeIPv6())
    {
        return false;
    }

    // 初期化成功メッセージ
    LogInitializationSuccessIPv6(bindAddr);
    return true;
}

bool PacketCapture::CreateRawSocket()
{
    m_socket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (m_socket == INVALID_SOCKET)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to create raw socket", error);
        LogSocketError(IDS_ERROR_RAW_SOCKET_FAILED, error);
        return false;
    }
    return true;
}

bool PacketCapture::CreateRawSocketIPv6()
{
    m_socketIPv6 = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6);
    if (m_socketIPv6 == INVALID_SOCKET)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to create IPv6 raw socket", error);
        return false;
    }
    return true;
}

bool PacketCapture::GetLocalAddressAndBind(sockaddr_in& bindAddr)
{
    // ホスト名取得
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to get hostname", error);
        LogWindow::GetInstance().AddLog(
            UIHelper::LoadStringFromResource(IDS_ERROR_HOSTNAME_FAILED));
        CloseSocket();
        return false;
    }

    // アドレス情報取得
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to get address info", error);
        LogWindow::GetInstance().AddLog(
            UIHelper::LoadStringFromResource(IDS_ERROR_ADDRINFO_FAILED));
        CloseSocket();
        return false;
    }

    // バインド用アドレス設定
    bindAddr = { 0 };
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = 0;
    bindAddr.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;

    // ソケットバインド
    bool bindSuccess = (bind(m_socket, reinterpret_cast<sockaddr*>(&bindAddr), 
                             sizeof(bindAddr)) != SOCKET_ERROR);
    
    if (!bindSuccess)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to bind socket", error);
        
        WCHAR msg[512];
        swprintf_s(msg, 
            UIHelper::LoadStringFromResource(IDS_ERROR_BIND_FAILED).c_str(), 
            error);
        LogWindow::GetInstance().AddLog(msg);
    }

    freeaddrinfo(result);

    if (!bindSuccess)
    {
        CloseSocket();
        return false;
    }

    return true;
}

bool PacketCapture::GetLocalAddressAndBindIPv6(sockaddr_in6& bindAddr)
{
    // ホスト名取得
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to get hostname for IPv6", error);
        CloseSocketIPv6();
        return false;
    }

    // アドレス情報取得
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to get IPv6 address info", error);
        CloseSocketIPv6();
        return false;
    }

    // バインド用アドレス設定
    bindAddr = { 0 };
    bindAddr.sin6_family = AF_INET6;
    bindAddr.sin6_port = 0;
    memcpy(&bindAddr.sin6_addr, 
           &reinterpret_cast<sockaddr_in6*>(result->ai_addr)->sin6_addr,
           sizeof(bindAddr.sin6_addr));

    // ソケットバインド
    bool bindSuccess = (bind(m_socketIPv6, reinterpret_cast<sockaddr*>(&bindAddr), 
                             sizeof(bindAddr)) != SOCKET_ERROR);
    
    if (!bindSuccess)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to bind IPv6 socket", error);
    }

    freeaddrinfo(result);

    if (!bindSuccess)
    {
        CloseSocketIPv6();
        return false;
    }

    return true;
}

bool PacketCapture::ConfigureSocketOptions()
{
    // 受信タイムアウト設定
    DWORD timeout = RECV_TIMEOUT_MS;
    if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, 
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == SOCKET_ERROR)
    {
        NetworkLogger::GetInstance().LogError(L"Failed to set socket timeout", 
                                             WSAGetLastError());
    }

    // 受信バッファサイズ設定
    int recvBufferSize = SOCKET_BUFFER_SIZE;
    if (setsockopt(m_socket, SOL_SOCKET, SO_RCVBUF, 
                   reinterpret_cast<const char*>(&recvBufferSize), 
                   sizeof(recvBufferSize)) == SOCKET_ERROR)
    {
        NetworkLogger::GetInstance().LogError(L"Failed to set receive buffer size", 
                                             WSAGetLastError());
    }

    return true;
}

bool PacketCapture::EnablePromiscuousMode()
{
    DWORD flag = RCVALL_ON;
    if (ioctlsocket(m_socket, SIO_RCVALL, &flag) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to set promiscuous mode", error);
        LogSocketError(IDS_ERROR_PROMISCUOUS_FAILED, error);
        CloseSocket();
        return false;
    }
    return true;
}

bool PacketCapture::EnablePromiscuousModeIPv6()
{
    DWORD flag = RCVALL_ON;
    if (ioctlsocket(m_socketIPv6, SIO_RCVALL, &flag) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to set IPv6 promiscuous mode", error);
        CloseSocketIPv6();
        return false;
    }
    return true;
}

void PacketCapture::LogSocketError(int resourceId, int errorCode)
{
    WCHAR msg[512];
    swprintf_s(msg, 
        UIHelper::LoadStringFromResource(resourceId).c_str(), 
        errorCode);
    
    std::wstring fullMsg = msg;
    if (errorCode == WSAEACCES)
    {
        fullMsg += UIHelper::LoadStringFromResource(IDS_ERROR_ADMIN_REQUIRED);
    }
    
    LogWindow::GetInstance().AddLog(fullMsg);
}

void PacketCapture::LogInitializationSuccess(const sockaddr_in& bindAddr)
{
    WCHAR msg[512];
    swprintf_s(msg, 
        UIHelper::LoadStringFromResource(IDS_RAW_SOCKET_INITIALIZED).c_str(),
        static_cast<int>(bindAddr.sin_addr.S_un.S_un_b.s_b1),
        static_cast<int>(bindAddr.sin_addr.S_un.S_un_b.s_b2),
        static_cast<int>(bindAddr.sin_addr.S_un.S_un_b.s_b3),
        static_cast<int>(bindAddr.sin_addr.S_un.S_un_b.s_b4));
    LogWindow::GetInstance().AddLog(msg);
}

void PacketCapture::LogInitializationSuccessIPv6(const sockaddr_in6& bindAddr)
{
    char ipv6Str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &bindAddr.sin6_addr, ipv6Str, INET6_ADDRSTRLEN);
    
    WCHAR msg[512];
    swprintf_s(msg, L"IPv6 Raw socket initialized on %S", ipv6Str);
    LogWindow::GetInstance().AddLog(msg);
}

void PacketCapture::CloseSocket()
{
    if (m_socket != INVALID_SOCKET)
    {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
}

void PacketCapture::CloseSocketIPv6()
{
    if (m_socketIPv6 != INVALID_SOCKET)
    {
        closesocket(m_socketIPv6);
        m_socketIPv6 = INVALID_SOCKET;
    }
}

void PacketCapture::CloseLoopbackSocket()
{
    if (m_loopbackSocket != INVALID_SOCKET)
    {
        closesocket(m_loopbackSocket);
        m_loopbackSocket = INVALID_SOCKET;
    }
}

bool PacketCapture::StartCapture(USHORT targetPort)
{
    if (m_isCapturing)
    {
        NetworkLogger::GetInstance().LogError(L"Already capturing", 0);
        LogWindow::GetInstance().AddLog(
            UIHelper::LoadStringFromResource(IDS_ALREADY_CAPTURING));
        return false;
    }

    m_targetPort = targetPort;

    // IPv4ソケット初期化
    bool ipv4Success = InitializeRawSocket();
    
    // IPv6ソケット初期化
    bool ipv6Success = InitializeRawSocketIPv6();
    
    // ループバックソケット初期化
    bool loopbackSuccess = InitializeLoopbackSocket();

    if (!ipv4Success && !ipv6Success && !loopbackSuccess)
    {
        return false;
    }

    m_isCapturing = true;
    
    // IPv4キャプチャスレッド
    if (ipv4Success)
    {
        m_captureThread = std::thread(&PacketCapture::CaptureThread, this);
    }
    
    // IPv6キャプチャスレッド
    if (ipv6Success)
    {
        m_captureThreadIPv6 = std::thread(&PacketCapture::CaptureThreadIPv6, this);
    }
    
    // ループバックキャプチャスレッド
    if (loopbackSuccess)
    {
        m_loopbackThread = std::thread(&PacketCapture::CaptureThreadLoopback, this);
    }

    LogCaptureStarted(targetPort);
    return true;
}

void PacketCapture::StopCapture()
{
    if (!m_isCapturing)
    {
        return;
    }

    m_isCapturing = false;
    CloseSocket();
    CloseSocketIPv6();
    CloseLoopbackSocket();

    if (m_captureThread.joinable())
    {
        m_captureThread.join();
    }
    
    if (m_captureThreadIPv6.joinable())
    {
        m_captureThreadIPv6.join();
    }
    
    if (m_loopbackThread.joinable())
    {
        m_loopbackThread.join();
    }

    LogCaptureStopped();
}

void PacketCapture::LogCaptureStarted(USHORT port)
{
    WCHAR msg[256];
    swprintf_s(msg, 
        UIHelper::LoadStringFromResource(IDS_CAPTURE_STARTED).c_str(), 
        port);
    NetworkLogger::GetInstance().LogRequest(msg, L"CAPTURE");
    LogWindow::GetInstance().AddLog(msg);
}

void PacketCapture::LogCaptureStopped()
{
    NetworkLogger::GetInstance().LogRequest(L"Stopped capturing", L"CAPTURE");
    LogWindow::GetInstance().AddLog(
        UIHelper::LoadStringFromResource(IDS_CAPTURE_STOPPED));
}

void PacketCapture::CaptureThread()
{
    std::vector<BYTE> buffer(RECV_BUFFER_SIZE);
    DWORD packetCount = 0;

    LogCaptureThreadStarted();

    while (m_isCapturing)
    {
        int bytesReceived = recv(m_socket, 
                                reinterpret_cast<char*>(buffer.data()), 
                                RECV_BUFFER_SIZE, 0);
        
        if (bytesReceived > 0)
        {
            packetCount++;
            ParseIPPacket(buffer.data(), bytesReceived);
        }
        else if (bytesReceived == 0)
        {
            break;
        }
        else if (!HandleSocketError(WSAGetLastError()))
        {
            break;
        }
    }

    LogCaptureThreadEnded(packetCount);
}

void PacketCapture::CaptureThreadIPv6()
{
    std::vector<BYTE> buffer(RECV_BUFFER_SIZE);
    DWORD packetCount = 0;

    WCHAR msg[256];
    swprintf_s(msg, L"IPv6 capture thread started on port %u", m_targetPort);
    LogWindow::GetInstance().AddLogThreadSafe(msg);

    while (m_isCapturing)
    {
        int bytesReceived = recv(m_socketIPv6, 
                                reinterpret_cast<char*>(buffer.data()), 
                                RECV_BUFFER_SIZE, 0);
        
        if (bytesReceived > 0)
        {
            packetCount++;
            ParseIPv6Packet(buffer.data(), bytesReceived);
        }
        else if (bytesReceived == 0)
        {
            break;
        }
        else if (!HandleSocketError(WSAGetLastError()))
        {
            break;
        }
    }

    swprintf_s(msg, L"IPv6 capture thread ended. Packets captured: %u", packetCount);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

void PacketCapture::CaptureThreadLoopback()
{
    std::vector<BYTE> buffer(RECV_BUFFER_SIZE);
    DWORD packetCount = 0;

    WCHAR msg[256];
    swprintf_s(msg, L"Loopback capture thread started on port %u", m_targetPort);
    LogWindow::GetInstance().AddLogThreadSafe(msg);

    while (m_isCapturing)
    {
        int bytesReceived = recv(m_loopbackSocket, 
                                reinterpret_cast<char*>(buffer.data()), 
                                RECV_BUFFER_SIZE, 0);
        
        if (bytesReceived > 0)
        {
            packetCount++;
            ParseIPPacket(buffer.data(), bytesReceived);
        }
        else if (bytesReceived == 0)
        {
            break;
        }
        else if (!HandleSocketError(WSAGetLastError()))
        {
            break;
        }
    }

    swprintf_s(msg, L"Loopback capture thread ended. Packets captured: %u", packetCount);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

bool PacketCapture::HandleSocketError(int error)
{
    if (error == WSAETIMEDOUT)
    {
        return true;
    }
    
    if (error == WSAENOTSOCK || error == WSAEINTR || !m_isCapturing)
    {
        return false;
    }
    
    NetworkLogger::GetInstance().LogError(L"Socket error during capture", error);
    
    WCHAR errMsg[256];
    swprintf_s(errMsg, 
        UIHelper::LoadStringFromResource(IDS_SOCKET_ERROR).c_str(), 
        error);
    LogWindow::GetInstance().AddLogThreadSafe(errMsg);
    
    return false;
}

void PacketCapture::LogCaptureThreadStarted()
{
    WCHAR msg[256];
    swprintf_s(msg, 
        UIHelper::LoadStringFromResource(IDS_CAPTURE_THREAD_STARTED).c_str(), 
        m_targetPort);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

void PacketCapture::LogCaptureThreadEnded(DWORD packetCount)
{
    WCHAR msg[256];
    swprintf_s(msg, 
        UIHelper::LoadStringFromResource(IDS_CAPTURE_THREAD_ENDED).c_str(), 
        packetCount);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

std::string PacketCapture::IPToString(DWORD ip)
{
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);
    return std::string(str);
}

std::string PacketCapture::IPv6ToString(const BYTE* ipv6Addr)
{
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ipv6Addr, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

bool PacketCapture::ParseIPPacket(const BYTE* buffer, DWORD size)
{
    if (size < sizeof(IPHeader))
    {
        return false;
    }

    const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(buffer);
    
    DWORD ipHeaderLen = ipHeader->headerLen * 4;
    if (ipHeaderLen < 20 || ipHeaderLen > size)
    {
        return false;
    }

    const BYTE* payload = buffer + ipHeaderLen;
    DWORD payloadLen = size - ipHeaderLen;

    switch (ipHeader->protocol)
    {
    case 6:  // TCP
        return ParseTCPPacket(buffer, ipHeaderLen, payload, payloadLen);
    case 17: // UDP
        return ParseUDPPacket(buffer, ipHeaderLen, payload, payloadLen);
    default:
        return false;
    }
}

bool PacketCapture::ParseIPv6Packet(const BYTE* buffer, DWORD size)
{
    if (size < sizeof(IPv6Header))
    {
        return false;
    }

    const IPv6Header* ipv6Header = reinterpret_cast<const IPv6Header*>(buffer);
    
    const BYTE* payload = buffer + sizeof(IPv6Header);
    DWORD payloadLen = size - sizeof(IPv6Header);

    switch (ipv6Header->nextHeader)
    {
    case 6:  // TCP
        return ParseTCPPacketIPv6(buffer, sizeof(IPv6Header), payload, payloadLen);
    case 17: // UDP
        return ParseUDPPacketIPv6(buffer, sizeof(IPv6Header), payload, payloadLen);
    default:
        return false;
    }
}

bool PacketCapture::ParseTCPPacket(const BYTE* ipHeader, DWORD ipHeaderLen, 
                                   const BYTE* tcpData, DWORD tcpDataLen)
{
    if (tcpDataLen < sizeof(TCPHeader))
    {
        return false;
    }

    const IPHeader* ip = reinterpret_cast<const IPHeader*>(ipHeader);
    const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(tcpData);

    USHORT srcPort = ntohs(tcp->sourcePort);
    USHORT dstPort = ntohs(tcp->destPort);

    if (!IsTargetPort(srcPort, dstPort))
    {
        return false;
    }

    PacketInfo info;
    FillPacketInfo(info, ip, srcPort, dstPort, "TCP");
    
    DWORD tcpHeaderLen = tcp->dataOffset * 4;
    ExtractPayload(info, tcpData, tcpHeaderLen, tcpDataLen);

    GetLocalTime(&info.timestamp);

    NotifyPacket(info);
    return true;
}

bool PacketCapture::ParseUDPPacket(const BYTE* ipHeader, DWORD ipHeaderLen,
                                   const BYTE* udpData, DWORD udpDataLen)
{
    if (udpDataLen < sizeof(UDPHeader))
    {
        return false;
    }

    const IPHeader* ip = reinterpret_cast<const IPHeader*>(ipHeader);
    const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(udpData);

    USHORT srcPort = ntohs(udp->sourcePort);
    USHORT dstPort = ntohs(udp->destPort);

    if (!IsTargetPort(srcPort, dstPort))
    {
        return false;
    }

    PacketInfo info;
    FillPacketInfo(info, ip, srcPort, dstPort, "UDP");
    
    ExtractPayload(info, udpData, sizeof(UDPHeader), udpDataLen);

    GetLocalTime(&info.timestamp);

    NotifyPacket(info);
    return true;
}

bool PacketCapture::ParseTCPPacketIPv6(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
                                       const BYTE* tcpData, DWORD tcpDataLen)
{
    if (tcpDataLen < sizeof(TCPHeader))
    {
        return false;
    }

    const IPv6Header* ip = reinterpret_cast<const IPv6Header*>(ipv6Header);
    const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(tcpData);

    USHORT srcPort = ntohs(tcp->sourcePort);
    USHORT dstPort = ntohs(tcp->destPort);

    if (!IsTargetPort(srcPort, dstPort))
    {
        return false;
    }

    PacketInfo info;
    FillPacketInfoIPv6(info, ip, srcPort, dstPort, "TCP");
    
    DWORD tcpHeaderLen = tcp->dataOffset * 4;
    ExtractPayload(info, tcpData, tcpHeaderLen, tcpDataLen);

    GetLocalTime(&info.timestamp);

    NotifyPacket(info);
    return true;
}

bool PacketCapture::ParseUDPPacketIPv6(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
                                       const BYTE* udpData, DWORD udpDataLen)
{
    if (udpDataLen < sizeof(UDPHeader))
    {
        return false;
    }

    const IPv6Header* ip = reinterpret_cast<const IPv6Header*>(ipv6Header);
    const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(udpData);

    USHORT srcPort = ntohs(udp->sourcePort);
    USHORT dstPort = ntohs(udp->destPort);

    if (!IsTargetPort(srcPort, dstPort))
    {
        return false;
    }

    PacketInfo info;
    FillPacketInfoIPv6(info, ip, srcPort, dstPort, "UDP");
    
    ExtractPayload(info, udpData, sizeof(UDPHeader), udpDataLen);

    GetLocalTime(&info.timestamp);

    NotifyPacket(info);
    return true;
}

bool PacketCapture::IsTargetPort(USHORT srcPort, USHORT dstPort) const
{
    return (srcPort == m_targetPort || dstPort == m_targetPort);
}

void PacketCapture::FillPacketInfo(PacketInfo& info, const IPHeader* ip, 
                                   USHORT srcPort, USHORT dstPort, 
                                   const char* protocol)
{
    info.sourceIP = IPToString(ip->sourceIP);
    info.destIP = IPToString(ip->destIP);
    info.sourcePort = srcPort;
    info.destPort = dstPort;
    info.protocol = protocol;
    info.isIPv6 = false;
}

void PacketCapture::FillPacketInfoIPv6(PacketInfo& info, const IPv6Header* ip,
                                       USHORT srcPort, USHORT dstPort,
                                       const char* protocol)
{
    info.sourceIP = IPv6ToString(ip->sourceIP);
    info.destIP = IPv6ToString(ip->destIP);
    info.sourcePort = srcPort;
    info.destPort = dstPort;
    info.protocol = protocol;
    info.isIPv6 = true;
}

void PacketCapture::ExtractPayload(PacketInfo& info, const BYTE* data, 
                                   DWORD headerLen, DWORD totalLen)
{
    if (headerLen >= 20 && totalLen > headerLen)
    {
        DWORD payloadSize = totalLen - headerLen;
        info.dataSize = payloadSize;
        
        const BYTE* payload = data + headerLen;
        info.data.assign(payload, payload + payloadSize);
    }
    else
    {
        info.dataSize = 0;
        info.data.clear();
    }
}

void PacketCapture::NotifyPacket(const PacketInfo& info)
{
    if (m_callback)
    {
        m_callback(info);
    }
}