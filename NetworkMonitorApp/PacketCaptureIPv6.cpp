#include "framework.h"
#define NOMINMAX
#include "PacketCaptureIPv6.h"
#include "NetworkLogger.h"
#include "LogWindow.h"
#include "UIHelper.h"
#include "Resource.h"
#include <ws2tcpip.h>

// 定数定義
namespace
{
    constexpr int RECV_BUFFER_SIZE = 65536;     // 64KB
}

PacketCaptureIPv6::PacketCaptureIPv6()
    : m_socket(INVALID_SOCKET)
    , m_targetPort(0)
    , m_isCapturing(false)
{
    if (!InitializeWinsock())
    {
        LogWindow::GetInstance().AddLog(L"Failed to initialize Winsock for IPv6");
    }
}

PacketCaptureIPv6::~PacketCaptureIPv6()
{
    StopCapture();
    WSACleanup();
}

bool PacketCaptureIPv6::InitializeWinsock()
{
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        NetworkLogger::GetInstance().LogError(L"WSAStartup failed for IPv6", result);
        return false;
    }
    return true;
}

void PacketCaptureIPv6::SetPacketCallback(std::function<void(const PacketInfo&)> callback)
{
    m_callback = callback;
}

bool PacketCaptureIPv6::InitializeRawSocket(const std::wstring& targetIP)
{
    if (!CreateRawSocket())
    {
        return false;
    }

    sockaddr_in6 bindAddr = {};
    if (targetIP.empty())
    {
        // 従来通りローカルアドレス取得してバインド
        if (!GetLocalAddressAndBind(bindAddr))
        {
            return false;
        }
    }
    else
    {
        // IPアドレスが有効かつ使用可能か確認
        if (!IsValidUsableIPAddress(targetIP))
        {
            LogWindow::GetInstance().AddLog(L"Invalid IPv6 address specified for binding.");
            CloseSocket();
            return false;
        }
        bindAddr = {};
        bindAddr.sin6_family = AF_INET6;
        bindAddr.sin6_port = 0;
        char ipStr[INET6_ADDRSTRLEN] = {0};
        size_t converted = 0;
        wcstombs_s(&converted, ipStr, targetIP.c_str(), _TRUNCATE);
        if (inet_pton(AF_INET6, ipStr, &bindAddr.sin6_addr) != 1)
        {
            LogWindow::GetInstance().AddLog(L"Failed to convert IPv6 address for binding.");
            CloseSocket();
            return false;
        }
        bool bindSuccess = (bind(m_socket, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) != SOCKET_ERROR);
        if (!bindSuccess)
        {
            int error = WSAGetLastError();
            NetworkLogger::GetInstance().LogError(L"Failed to bind IPv6 socket to specified address", error);
            CloseSocket();
            return false;
        }
    }

    if (!EnablePromiscuousMode())
    {
        return false;
    }

    LogInitializationSuccess(bindAddr);
    return true;
}

bool PacketCaptureIPv6::CreateRawSocket()
{
    m_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6);
    if (m_socket == INVALID_SOCKET)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to create IPv6 raw socket", error);
        return false;
    }
    return true;
}

bool PacketCaptureIPv6::GetLocalAddressAndBind(sockaddr_in6& bindAddr)
{
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to get hostname for IPv6", error);
        CloseSocket();
        return false;
    }

    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to get IPv6 address info", error);
        CloseSocket();
        return false;
    }

    bindAddr = { 0 };
    bindAddr.sin6_family = AF_INET6;
    bindAddr.sin6_port = 0;
    memcpy(&bindAddr.sin6_addr, 
           &reinterpret_cast<sockaddr_in6*>(result->ai_addr)->sin6_addr,
           sizeof(bindAddr.sin6_addr));

    bool bindSuccess = (bind(m_socket, reinterpret_cast<sockaddr*>(&bindAddr), 
                             sizeof(bindAddr)) != SOCKET_ERROR);
    
    if (!bindSuccess)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to bind IPv6 socket", error);
    }

    freeaddrinfo(result);

    if (!bindSuccess)
    {
        CloseSocket();
        return false;
    }

    return true;
}

bool PacketCaptureIPv6::EnablePromiscuousMode()
{
    DWORD flag = RCVALL_ON;
    if (ioctlsocket(m_socket, SIO_RCVALL, &flag) == SOCKET_ERROR)
    {
        int error = WSAGetLastError();
        NetworkLogger::GetInstance().LogError(L"Failed to set IPv6 promiscuous mode", error);
        CloseSocket();
        return false;
    }
    return true;
}

void PacketCaptureIPv6::LogInitializationSuccess(const sockaddr_in6& bindAddr)
{
    char ipv6Str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &bindAddr.sin6_addr, ipv6Str, INET6_ADDRSTRLEN);
    
    WCHAR msg[512];
    swprintf_s(msg, L"IPv6 Raw socket initialized on %S", ipv6Str);
    LogWindow::GetInstance().AddLog(msg);
}

void PacketCaptureIPv6::CloseSocket()
{
    if (m_socket != INVALID_SOCKET)
    {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
}

bool PacketCaptureIPv6::StartCapture(USHORT targetPort, const std::wstring& targetIP)
{
    if (m_isCapturing)
    {
        NetworkLogger::GetInstance().LogError(L"Already capturing IPv6", 0);
        return false;
    }

    m_targetPort = targetPort;

    if (!InitializeRawSocket(targetIP))
    {
        return false;
    }

    m_isCapturing = true;
    m_captureThread = std::thread(&PacketCaptureIPv6::CaptureThread, this);

    LogCaptureStarted(targetPort);
    return true;
}

void PacketCaptureIPv6::StopCapture()
{
    if (!m_isCapturing)
    {
        return;
    }

    m_isCapturing = false;
    CloseSocket();

    if (m_captureThread.joinable())
    {
        m_captureThread.join();
    }

    LogCaptureStopped();
}

bool PacketCaptureIPv6::IsCapturing() const
{
    return m_isCapturing;
}

void PacketCaptureIPv6::LogCaptureStarted(USHORT port)
{
    WCHAR msg[256];
    swprintf_s(msg, L"IPv6 capture started on port %u", port);
    NetworkLogger::GetInstance().LogRequest(msg, L"CAPTURE_IPv6");
    LogWindow::GetInstance().AddLog(msg);
}

void PacketCaptureIPv6::LogCaptureStopped()
{
    NetworkLogger::GetInstance().LogRequest(L"Stopped IPv6 capturing", L"CAPTURE_IPv6");
    LogWindow::GetInstance().AddLog(L"IPv6 capture stopped");
}

void PacketCaptureIPv6::CaptureThread()
{
    std::vector<BYTE> buffer(RECV_BUFFER_SIZE);
    DWORD packetCount = 0;

    WCHAR msg[256];
    swprintf_s(msg, L"IPv6 capture thread started on port %u", m_targetPort);
    LogWindow::GetInstance().AddLogThreadSafe(msg);

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

    swprintf_s(msg, L"IPv6 capture thread ended. Packets captured: %u", packetCount);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

bool PacketCaptureIPv6::HandleSocketError(int error)
{
    if (error == WSAETIMEDOUT)
    {
        return true;
    }
    
    if (error == WSAENOTSOCK || error == WSAEINTR || !m_isCapturing)
    {
        return false;
    }
    
    NetworkLogger::GetInstance().LogError(L"Socket error during IPv6 capture", error);
    
    WCHAR errMsg[256];
    swprintf_s(errMsg, L"IPv6 Socket error: %d", error);
    LogWindow::GetInstance().AddLogThreadSafe(errMsg);
    
    return false;
}

std::string PacketCaptureIPv6::IPToString(const BYTE* ipAddr)
{
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ipAddr, str, INET6_ADDRSTRLEN);
    return std::string(str);
}

bool PacketCaptureIPv6::ParseIPPacket(const BYTE* buffer, DWORD size)
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
        return ParseTCPPacket(buffer, sizeof(IPv6Header), payload, payloadLen);
    case 17: // UDP
        return ParseUDPPacket(buffer, sizeof(IPv6Header), payload, payloadLen);
    default:
        return false;
    }
}

bool PacketCaptureIPv6::ParseTCPPacket(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
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

bool PacketCaptureIPv6::ParseUDPPacket(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
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

bool PacketCaptureIPv6::IsTargetPort(USHORT srcPort, USHORT dstPort) const
{
    return (srcPort == m_targetPort || dstPort == m_targetPort);
}

void PacketCaptureIPv6::FillPacketInfoIPv6(PacketInfo& info, const IPv6Header* ip,
                                           USHORT srcPort, USHORT dstPort,
                                           const char* protocol)
{
    info.sourceIP = IPToString(ip->sourceIP);
    info.destIP = IPToString(ip->destIP);
    info.sourcePort = srcPort;
    info.destPort = dstPort;
    info.protocol = protocol;
    info.isIPv6 = true;
}

void PacketCaptureIPv6::ExtractPayload(PacketInfo& info, const BYTE* data, 
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

void PacketCaptureIPv6::NotifyPacket(const PacketInfo& info)
{
    if (m_callback)
    {
        m_callback(info);
    }
}

bool PacketCaptureIPv6::IsValidUsableIPAddress(const std::wstring& ip)
{
    if (ip.empty()) return false;

    char ipStr[INET6_ADDRSTRLEN] = {0};
    size_t converted = 0;
    wcstombs_s(&converted, ipStr, ip.c_str(), _TRUNCATE);

    sockaddr_in6 sa6 = {};
    if (inet_pton(AF_INET6, ipStr, &(sa6.sin6_addr)) != 1)
        return false;

    // ::/128は除外
    static const unsigned char zero[16] = {0};
    if (memcmp(sa6.sin6_addr.s6_addr, zero, 16) == 0)
        return false;

    return true;
}