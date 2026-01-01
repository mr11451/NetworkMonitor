#include "framework.h"
#define NOMINMAX
#include "PacketCaptureIPv4.h"
#include "NetworkLogger.h"
#include "LogWindow.h"
#include "UIHelper.h"
#include "Resource.h"
#include <ws2tcpip.h>

// 定数定義
namespace
{
    constexpr int RECV_BUFFER_SIZE = 65536;     // 64KB
    constexpr int SOCKET_BUFFER_SIZE = 256 * 1024; // 256KB
    constexpr DWORD RECV_TIMEOUT_MS = 5000;     // 5秒
}

PacketCaptureIPv4::PacketCaptureIPv4()
    : m_socket(INVALID_SOCKET)
    , m_targetPort(0)
    , m_isCapturing(false)
{
    if (!InitializeWinsock())
    {
        LogWindow::GetInstance().AddLog(
            UIHelper::LoadStringFromResource(IDS_ERROR_WSASTARTUP_FAILED));
    }
}

PacketCaptureIPv4::~PacketCaptureIPv4()
{
    StopCapture();
    WSACleanup();
}

bool PacketCaptureIPv4::InitializeWinsock()
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

void PacketCaptureIPv4::SetPacketCallback(std::function<void(const PacketInfo&)> callback)
{
    m_callback = callback;
}

bool PacketCaptureIPv4::InitializeRawSocket(const std::wstring& targetIP)
{
    if (!CreateRawSocket())
    {
        return false;
    }

    sockaddr_in bindAddr = {};
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
            LogWindow::GetInstance().AddLog(L"Invalid IPv4 address specified for binding.");
            CloseSocket();
            return false;
        }
        bindAddr = {};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_port = 0;
        char ipStr[INET_ADDRSTRLEN] = {0};
        size_t converted = 0;
        wcstombs_s(&converted, ipStr, targetIP.c_str(), _TRUNCATE);
        if (inet_pton(AF_INET, ipStr, &bindAddr.sin_addr) != 1)
        {
            LogWindow::GetInstance().AddLog(L"Failed to convert IPv4 address for binding.");
            CloseSocket();
            return false;
        }
        bool bindSuccess = (bind(m_socket, reinterpret_cast<sockaddr*>(&bindAddr), sizeof(bindAddr)) != SOCKET_ERROR);
        if (!bindSuccess)
        {
            int error = WSAGetLastError();
            NetworkLogger::GetInstance().LogError(L"Failed to bind IPv4 socket to specified address", error);
            CloseSocket();
            return false;
        }
    }

    if (!ConfigureSocketOptions())
    {
        return false;
    }

    if (!EnablePromiscuousMode())
    {
        return false;
    }

    LogInitializationSuccess(bindAddr);
    return true;
}

bool PacketCaptureIPv4::CreateRawSocket()
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

bool PacketCaptureIPv4::GetLocalAddressAndBind(sockaddr_in& bindAddr)
{
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

    bindAddr = { 0 };
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = 0;
    bindAddr.sin_addr = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr;

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

bool PacketCaptureIPv4::ConfigureSocketOptions()
{
    DWORD timeout = RECV_TIMEOUT_MS;
    if (setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, 
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout)) == SOCKET_ERROR)
    {
        NetworkLogger::GetInstance().LogError(L"Failed to set socket timeout", 
                                             WSAGetLastError());
    }

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

bool PacketCaptureIPv4::EnablePromiscuousMode()
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

void PacketCaptureIPv4::LogSocketError(int resourceId, int errorCode)
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

void PacketCaptureIPv4::LogInitializationSuccess(const sockaddr_in& bindAddr)
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

void PacketCaptureIPv4::CloseSocket()
{
    if (m_socket != INVALID_SOCKET)
    {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
}

bool PacketCaptureIPv4::StartCapture(USHORT targetPort, const std::wstring& targetIP)
{
    if (m_isCapturing)
    {
        NetworkLogger::GetInstance().LogError(L"Already capturing", 0);
        LogWindow::GetInstance().AddLog(
            UIHelper::LoadStringFromResource(IDS_ALREADY_CAPTURING));
        return false;
    }

    m_targetPort = targetPort;

    if (!InitializeRawSocket(targetIP))
    {
        return false;
    }

    m_isCapturing = true;
    m_captureThread = std::thread(&PacketCaptureIPv4::CaptureThread, this);

    LogCaptureStarted(targetPort);
    return true;
}

void PacketCaptureIPv4::StopCapture()
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

bool PacketCaptureIPv4::IsCapturing() const
{
    return m_isCapturing;
}

void PacketCaptureIPv4::LogCaptureStarted(USHORT port)
{
    WCHAR msg[256];
    swprintf_s(msg, 
        UIHelper::LoadStringFromResource(IDS_CAPTURE_STARTED).c_str(), 
        port);
    NetworkLogger::GetInstance().LogRequest(msg, L"CAPTURE_IPv4");
    LogWindow::GetInstance().AddLog(msg);
}

void PacketCaptureIPv4::LogCaptureStopped()
{
    NetworkLogger::GetInstance().LogRequest(L"Stopped IPv4 capturing", L"CAPTURE_IPv4");
    LogWindow::GetInstance().AddLog(L"IPv4 " + 
        UIHelper::LoadStringFromResource(IDS_CAPTURE_STOPPED));
}

void PacketCaptureIPv4::CaptureThread()
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

bool PacketCaptureIPv4::HandleSocketError(int error)
{
    if (error == WSAETIMEDOUT)
    {
        return true;
    }
    
    if (error == WSAENOTSOCK || error == WSAEINTR || !m_isCapturing)
    {
        return false;
    }
    
    NetworkLogger::GetInstance().LogError(L"Socket error during IPv4 capture", error);
    
    WCHAR errMsg[256];
    swprintf_s(errMsg, 
        UIHelper::LoadStringFromResource(IDS_SOCKET_ERROR).c_str(), 
        error);
    LogWindow::GetInstance().AddLogThreadSafe(errMsg);
    
    return false;
}

void PacketCaptureIPv4::LogCaptureThreadStarted()
{
    WCHAR msg[256];
    swprintf_s(msg, L"IPv4 capture thread started on port %u", m_targetPort);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

void PacketCaptureIPv4::LogCaptureThreadEnded(DWORD packetCount)
{
    WCHAR msg[256];
    swprintf_s(msg, L"IPv4 capture thread ended. Packets captured: %u", packetCount);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

std::string PacketCaptureIPv4::IPToString(DWORD ip)
{
    struct in_addr addr;
    addr.S_un.S_addr = ip;
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, str, INET_ADDRSTRLEN);
    return std::string(str);
}

bool PacketCaptureIPv4::ParseIPPacket(const BYTE* buffer, DWORD size)
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

bool PacketCaptureIPv4::ParseTCPPacket(const BYTE* ipHeader, DWORD ipHeaderLen, 
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

bool PacketCaptureIPv4::ParseUDPPacket(const BYTE* ipHeader, DWORD ipHeaderLen,
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

bool PacketCaptureIPv4::IsTargetPort(USHORT srcPort, USHORT dstPort) const
{
    return (srcPort == m_targetPort || dstPort == m_targetPort);
}

void PacketCaptureIPv4::FillPacketInfo(PacketInfo& info, const IPHeader* ip, 
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

void PacketCaptureIPv4::ExtractPayload(PacketInfo& info, const BYTE* data, 
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

void PacketCaptureIPv4::NotifyPacket(const PacketInfo& info)
{
    if (m_callback)
    {
        m_callback(info);
    }
}

bool PacketCaptureIPv4::IsValidUsableIPAddress(const std::wstring& ip)
{
    if (ip.empty()) return false;

    char ipStr[INET_ADDRSTRLEN] = {0};
    size_t converted = 0;
    wcstombs_s(&converted, ipStr, ip.c_str(), _TRUNCATE);

    sockaddr_in sa4 = {};
    if (inet_pton(AF_INET, ipStr, &(sa4.sin_addr)) != 1)
        return false;

    // 0.0.0.0, 255.255.255.255, 127.x.x.x などは除外
    unsigned long addr = ntohl(sa4.sin_addr.s_addr);
    if (addr == 0 || addr == 0xFFFFFFFF || (addr >> 24) == 127)
        return false;

    return true;
}