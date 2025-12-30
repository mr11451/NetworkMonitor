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
#include "PacketInfo.h"
#include "ProtocolHeaders.h"  // 共通ヘッダーをインクルード

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class PacketCaptureIPv4
{
public:
    PacketCaptureIPv4();
    ~PacketCaptureIPv4();

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
    
    // ソケット管理
    void CloseSocket();
    
    // ログ関連
    void LogSocketError(int resourceId, int errorCode);
    void LogInitializationSuccess(const sockaddr_in& bindAddr);
    void LogCaptureStarted(USHORT port);
    void LogCaptureStopped();
    void LogCaptureThreadStarted();
    void LogCaptureThreadEnded(DWORD packetCount);
    
    // キャプチャスレッド
    void CaptureThread();
    bool HandleSocketError(int error);
    
    // パケット解析
    bool ParseIPPacket(const BYTE* buffer, DWORD size);
    bool ParseTCPPacket(const BYTE* ipHeader, DWORD ipHeaderLen, 
                        const BYTE* tcpData, DWORD tcpDataLen);
    bool ParseUDPPacket(const BYTE* ipHeader, DWORD ipHeaderLen, 
                        const BYTE* udpData, DWORD udpDataLen);
    
    // ヘルパー関数
    bool IsTargetPort(USHORT srcPort, USHORT dstPort) const;
    void FillPacketInfo(PacketInfo& info, const IPHeader* ip,
                       USHORT srcPort, USHORT dstPort, const char* protocol);
    void ExtractPayload(PacketInfo& info, const BYTE* data, 
                       DWORD headerLen, DWORD totalLen);
    void NotifyPacket(const PacketInfo& info);
    std::string IPToString(DWORD ip);

    // メンバー変数
    SOCKET m_socket;
    USHORT m_targetPort;
    std::atomic<bool> m_isCapturing;
    std::thread m_captureThread;
    std::function<void(const PacketInfo&)> m_callback;
};