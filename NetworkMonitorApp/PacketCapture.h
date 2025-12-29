#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include "PacketInfo.h" // 追加

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// 前方宣言
struct IPHeader;
struct IPv6Header;
struct TCPHeader;
struct UDPHeader;

class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    bool StartCapture(USHORT targetPort);
    void StopCapture();
    bool IsCapturing() const { return m_isCapturing; }
    
    void SetPacketCallback(std::function<void(const PacketInfo&)> callback);

private:
    // 初期化関連
    bool InitializeWinsock();
    bool InitializeRawSocket();
    bool CreateRawSocket();
    bool GetLocalAddressAndBind(sockaddr_in& bindAddr);
    bool ConfigureSocketOptions();
    bool EnablePromiscuousMode();
    
    // IPv6用初期化
    bool InitializeRawSocketIPv6();
    bool CreateRawSocketIPv6();
    bool GetLocalAddressAndBindIPv6(sockaddr_in6& bindAddr);
    bool EnablePromiscuousModeIPv6();
    
    // ループバック用初期化
    bool InitializeLoopbackSocket();
    
    // ソケット管理
    void CloseSocket();
    void CloseSocketIPv6();
    void CloseLoopbackSocket();
    
    // ログ関連
    void LogSocketError(int resourceId, int errorCode);
    void LogInitializationSuccess(const sockaddr_in& bindAddr);
    void LogInitializationSuccessIPv6(const sockaddr_in6& bindAddr);
    void LogCaptureStarted(USHORT port);
    void LogCaptureStopped();
    void LogCaptureThreadStarted();
    void LogCaptureThreadEnded(DWORD packetCount);
    
    // キャプチャスレッド
    void CaptureThread();
    void CaptureThreadIPv6();
    void CaptureThreadLoopback();
    bool HandleSocketError(int error);
    
    // パケット解析
    bool ParseIPPacket(const BYTE* buffer, DWORD size);
    bool ParseIPv6Packet(const BYTE* buffer, DWORD size);
    bool ParseTCPPacket(const BYTE* ipHeader, DWORD ipHeaderLen, 
                        const BYTE* tcpData, DWORD tcpDataLen);
    bool ParseUDPPacket(const BYTE* ipHeader, DWORD ipHeaderLen, 
                        const BYTE* udpData, DWORD udpDataLen);
    bool ParseTCPPacketIPv6(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
                            const BYTE* tcpData, DWORD tcpDataLen);
    bool ParseUDPPacketIPv6(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
                            const BYTE* udpData, DWORD udpDataLen);
    
    // ヘルパー関数
    bool IsTargetPort(USHORT srcPort, USHORT dstPort) const;
    void FillPacketInfo(PacketInfo& info, const IPHeader* ip,
                   USHORT srcPort, USHORT dstPort, const char* protocol);
    void FillPacketInfoIPv6(PacketInfo& info, const IPv6Header* ip,
                            USHORT srcPort, USHORT dstPort, const char* protocol);
    void ExtractPayload(PacketInfo& info, const BYTE* data, 
                       DWORD headerLen, DWORD totalLen);
    void NotifyPacket(const PacketInfo& info);
    std::string IPToString(DWORD ip);
    std::string IPv6ToString(const BYTE* ipv6Addr);

    // メンバー変数
    SOCKET m_socket;
    SOCKET m_socketIPv6;
    SOCKET m_loopbackSocket;
    USHORT m_targetPort;
    std::atomic<bool> m_isCapturing;
    std::thread m_captureThread;
    std::thread m_captureThreadIPv6;
    std::thread m_loopbackThread;
    std::function<void(const PacketInfo&)> m_callback;
};

// IPヘッダー構造体
#pragma pack(push, 1)
struct IPHeader
{
    BYTE  headerLen : 4;
    BYTE  version : 4;
    BYTE  tos;
    USHORT totalLen;
    USHORT id;
    USHORT fragOffset;
    BYTE  ttl;
    BYTE  protocol;
    USHORT checksum;
    DWORD sourceIP;
    DWORD destIP;
};

struct IPv6Header
{
    BYTE  trafficClassHigh : 4;
    BYTE  version : 4;
    BYTE  flowLabelHigh : 4;
    BYTE  trafficClassLow : 4;
    USHORT flowLabelLow;
    USHORT payloadLength;
    BYTE  nextHeader;
    BYTE  hopLimit;
    BYTE  sourceIP[16];
    BYTE  destIP[16];
};

struct TCPHeader
{
    USHORT sourcePort;
    USHORT destPort;
    DWORD seqNum;
    DWORD ackNum;
    BYTE reserved : 4;
    BYTE dataOffset : 4;
    BYTE flags;
    USHORT window;
    USHORT checksum;
    USHORT urgentPtr;
};

struct UDPHeader
{
    USHORT sourcePort;
    USHORT destPort;
    USHORT length;
    USHORT checksum;
};
#pragma pack(pop)