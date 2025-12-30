#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include "PacketInfo.h"
#include "ProtocolHeaders.h"

#pragma comment(lib, "ws2_32.lib")

class PacketCaptureIPv6
{
public:
    PacketCaptureIPv6();
    ~PacketCaptureIPv6();

    bool StartCapture(USHORT targetPort);
    void StopCapture();
    bool IsCapturing() const { return m_isCapturing; }
    
    void SetPacketCallback(std::function<void(const PacketInfo&)> callback);

private:
    // 初期化関連
    bool InitializeWinsock();
    bool InitializeRawSocketIPv6();
    bool CreateRawSocketIPv6();
    bool GetLocalAddressAndBindIPv6(sockaddr_in6& bindAddr);
    bool EnablePromiscuousModeIPv6();
    
    // ソケット管理
    void CloseSocketIPv6();
    
    // ログ関連
    void LogInitializationSuccessIPv6(const sockaddr_in6& bindAddr);
    void LogCaptureStarted(USHORT port);
    void LogCaptureStopped();
    
    // キャプチャスレッド
    void CaptureThreadIPv6();
    bool HandleSocketError(int error);
    
    // パケット解析
    bool ParseIPv6Packet(const BYTE* buffer, DWORD size);
    bool ParseTCPPacketIPv6(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
                            const BYTE* tcpData, DWORD tcpDataLen);
    bool ParseUDPPacketIPv6(const BYTE* ipv6Header, DWORD ipv6HeaderLen,
                            const BYTE* udpData, DWORD udpDataLen);
    
    // ヘルパー関数
    bool IsTargetPort(USHORT srcPort, USHORT dstPort) const;
    void FillPacketInfoIPv6(PacketInfo& info, const IPv6Header* ip,
                            USHORT srcPort, USHORT dstPort, const char* protocol);
    void ExtractPayload(PacketInfo& info, const BYTE* data, 
                       DWORD headerLen, DWORD totalLen);
    void NotifyPacket(const PacketInfo& info);
    std::string IPv6ToString(const BYTE* ipv6Addr);

    // メンバー変数
    SOCKET m_socketIPv6;
    USHORT m_targetPort;
    std::atomic<bool> m_isCapturing;
    std::thread m_captureThreadIPv6;
    std::function<void(const PacketInfo&)> m_callback;
};