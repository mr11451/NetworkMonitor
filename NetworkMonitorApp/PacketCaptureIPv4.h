#pragma once

#include <windows.h>
#include <winsock2.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include "PacketInfo.h"
#include "ProtocolHeaders.h"
#include <pcap/pcap.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class PacketCaptureIPv4
{
public:
    PacketCaptureIPv4();
    ~PacketCaptureIPv4();

    void SetPacketCallback(std::function<void(const PacketInfo&)> callback);
    bool InitializePcap(const std::wstring& targetIP);
    bool StartCapture(USHORT targetPort, const std::wstring& targetIP);
    void StopCapture();
    bool IsCapturing() const;

    // 追加: IPv4アドレスが有効かつ使用可能かチェック
    static bool IsValidUsableIPAddress(const std::wstring& ip);

    // 追加: npcapフィルタ設定
    bool SetPcapFilter(const std::wstring& targetIP);

private:
    // キャプチャスレッド
    void CaptureThread();
    void PacketHandler(u_char* param, const pcap_pkthdr* header, const u_char* pkt_data);
    
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

    // 追加: npcap用ハンドル
    pcap_t* m_pcapHandle = nullptr;
};