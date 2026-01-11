#include <WinSock2.h>
#include <windows.h>
#include "PacketCaptureIPv6.h"
#include "NetworkLogger.h"
#include "LogWindow.h"
#include "UIHelper.h"
#include "Resource.h"
#include <ws2tcpip.h>
#include <thread>
#include <vector>
#include <string>
#include <system_error>
#include <functional>
#include "PacketInfo.h"
#include <pcap/pcap.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <corecrt.h>
#include <cstdlib>
#include "ProtocolHeaders.h"
#include <in6addr.h>
#include <cstdio>
#include <pcap/bpf.h>
#include <string.h>
#include <string.h>
#include <pcap/dlt.h>

namespace
{
    constexpr int RECV_BUFFER_SIZE = 65536; // 64KB
}

// コンストラクタ
PacketCaptureIPv6::PacketCaptureIPv6()
    : m_pcapHandle(nullptr)
    , m_targetPort(0)
    , m_isCapturing(false)
{
    // npcapの初期化は不要
}

// デストラクタ
PacketCaptureIPv6::~PacketCaptureIPv6()
{
    StopCapture();
}

// パケットコールバック設定
void PacketCaptureIPv6::SetPacketCallback(std::function<void(const PacketInfo&)> callback)
{
    m_callback = callback;
}

// npcap初期化
bool PacketCaptureIPv6::InitializePcap(const std::wstring& targetIP)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_FINDALLDEVS_FAILED));
        return false;
    }

    // IPv6対応インターフェースを選択
    pcap_if_t* selected = nullptr;
    if (!targetIP.empty()) {
        // targetIPが指定されている場合、そのIPを持つインターフェースのみ選択
        char ipStr[INET6_ADDRSTRLEN] = {0};
        size_t converted = 0;
        wcstombs_s(&converted, ipStr, targetIP.c_str(), _TRUNCATE);
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            for (pcap_addr_t* a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET6) {
                    sockaddr_in6* sin6 = reinterpret_cast<sockaddr_in6*>(a->addr);
                    char devIpStr[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET6, &(sin6->sin6_addr), devIpStr, INET6_ADDRSTRLEN);
                    if (strcmp(ipStr, devIpStr) == 0) {
                        selected = d;
                        break;
                    }
                }
            }
            if (selected) break;
        }
    } else {
        // IP指定なしの場合は最初のIPv6インターフェース
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            for (pcap_addr_t* a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET6) {
                    selected = d;
                    break;
                }
            }
            if (selected) break;
        }
    }

    if (!selected) {
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_NO_IPV6_INTERFACE));
        pcap_freealldevs(alldevs);
        return false;
    }

    m_pcapHandle = pcap_open_live(selected->name, RECV_BUFFER_SIZE, 1, 1000, errbuf);
    if (!m_pcapHandle) {
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_OPEN_LIVE_FAILED));
        pcap_freealldevs(alldevs);
        return false;
    }

    // フィルタ設定
    if (!SetPcapFilter(targetIP)) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
        pcap_freealldevs(alldevs);
        return false;
    }

    LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_INITIALIZED_IPV6));
    pcap_freealldevs(alldevs);
    return true;
}

// フィルタ設定
bool PacketCaptureIPv6::SetPcapFilter(const std::wstring& targetIP)
{
    std::string filter;
    if (!targetIP.empty()) {
        char ipStr[INET6_ADDRSTRLEN] = {0};
        size_t converted = 0;
        wcstombs_s(&converted, ipStr, targetIP.c_str(), _TRUNCATE);
        filter = "ip6 and (src host " + std::string(ipStr) + " or dst host " + std::string(ipStr) + ")";
    } else {
        filter = "ip6";
    }
    if (m_targetPort > 0) {
        filter += " and (tcp port " + std::to_string(m_targetPort) + " or udp port " + std::to_string(m_targetPort) + ")";
    }

    bpf_program fp;
    if (pcap_compile(m_pcapHandle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_COMPILE_FAILED));
        return false;
    }
    if (pcap_setfilter(m_pcapHandle, &fp) == -1) {
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_SETFILTER_FAILED));
        pcap_freecode(&fp);
        return false;
    }
    pcap_freecode(&fp);
    return true;
}

// キャプチャ開始
bool PacketCaptureIPv6::StartCapture(USHORT targetPort, const std::wstring& targetIP)
{
    if (m_isCapturing) {
        NetworkLogger::GetInstance().LogError(L"Already capturing", 0);
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_ALREADY_CAPTURING));
        return false;
    }

    m_targetPort = targetPort;

    if (!InitializePcap(targetIP)) {
        return false;
    }

    m_isCapturing = true;
    m_captureThread = std::thread(&PacketCaptureIPv6::CaptureThread, this);

    WCHAR msg[256];
    swprintf_s(msg, L"IPv6 capture started (npcap) on port %u", targetPort);
    NetworkLogger::GetInstance().LogRequest(msg, L"CAPTURE_IPv6");
    LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_CAPTURE_STARTED_IPV6));
    return true;
}

// キャプチャ停止
void PacketCaptureIPv6::StopCapture()
{
    // すでに停止中なら何もしない
    if (!m_isCapturing && !m_captureThread.joinable()) {
        return;
    }

    // キャプチャフラグを下ろす
    m_isCapturing = false;

    // pcap_loopを中断（スレッド内でpcap_loopがブロックしている場合も安全に抜ける）
    if (m_pcapHandle) {
        pcap_breakloop(m_pcapHandle);
    }

    // スレッドがjoinableなら必ずjoin
    if (m_captureThread.joinable()) {
        try {
            m_captureThread.join();
        } catch (const std::system_error&) {
            // join失敗時も例外で落ちないように
        }
    }

    // pcapハンドルのクローズ
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
    }

    NetworkLogger::GetInstance().LogRequest(UIHelper::LoadStringFromResource(IDS_CAPTURE_STOPPED_IPV6), L"CAPTURE_IPv6");
    LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_CAPTURE_STOPPED_IPV6));
}

// キャプチャ中か判定
bool PacketCaptureIPv6::IsCapturing() const
{
    return m_isCapturing;
}

// キャプチャスレッド
void PacketCaptureIPv6::CaptureThread()
{
    WCHAR msg[256];
    swprintf_s(msg, UIHelper::LoadStringFromResource(IDS_CAPTURE_THREAD_STARTED).c_str(), m_targetPort);
    LogWindow::GetInstance().AddLogThreadSafe(msg);

    // 修正: pcap_loopのコールバックでparamにthisを渡し、ラムダ内で安全にPacketHandlerを呼び出す
    int res = pcap_loop(
        m_pcapHandle,
        0,
        [](u_char* param, const pcap_pkthdr* header, const u_char* pkt_data) {
            auto* self = reinterpret_cast<PacketCaptureIPv6*>(param);
            if (self) {
                self->PacketHandler(param, header, pkt_data);
            }
        },
        reinterpret_cast<u_char*>(this)); // paramにthisを渡す

    swprintf_s(msg, UIHelper::LoadStringFromResource(IDS_CAPTURE_THREAD_ENDED).c_str(), res);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

// staticメンバー関数として定義
void PacketCaptureIPv6::PacketHandler(u_char* param, const pcap_pkthdr* header, const u_char* pkt_data)
{
    auto* self = reinterpret_cast<PacketCaptureIPv6*>(param);
    if (!self->m_isCapturing) return;

    // データリンク層ヘッダサイズを判定（Ethernet:14, ループバック:4）
    int l2HeaderSize = sizeof(eth_header);
    int datalink = pcap_datalink(self->m_pcapHandle);
    if (datalink == DLT_NULL) {
        l2HeaderSize = 4;
    } else if (datalink == DLT_EN10MB) {
        l2HeaderSize = 14;
    }
    // 必要に応じて他のDLTも追加

    if (header->caplen <= static_cast<unsigned int>(l2HeaderSize)) return;

    const BYTE* ipv6Packet = pkt_data + l2HeaderSize;
    DWORD ipv6PacketLen = header->caplen - l2HeaderSize;

    self->ParseIPPacket(ipv6Packet, ipv6PacketLen);
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