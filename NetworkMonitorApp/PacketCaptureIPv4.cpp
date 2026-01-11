#include <WinSock2.h>
#include <windows.h>
#include "framework.h"
#include "PacketCaptureIPv4.h"
#include "NetworkLogger.h"
#include "LogWindow.h"
#include "UIHelper.h"
#include "Resource.h"
#include <pcap.h>
#include <thread>
#include <vector>
#include <string>
#include <pcap/pcap.h>
#include <functional>
#include "PacketInfo.h"
#include <ws2def.h>
#include <corecrt.h>
#include <cstdlib>
#include <ws2ipdef.h>
#include <WS2tcpip.h>
#include <cstdio>
#include <system_error>
#include "ProtocolHeaders.h"
#include <pcap/bpf.h>
#include <string.h>
#include <pcap/dlt.h>

namespace
{
    constexpr int RECV_BUFFER_SIZE = 65536; // 64KB
}

// コンストラクタ
PacketCaptureIPv4::PacketCaptureIPv4()
    : m_pcapHandle(nullptr)
    , m_targetPort(0)
    , m_isCapturing(false)
{
    // npcapの初期化は不要
}

// デストラクタ
PacketCaptureIPv4::~PacketCaptureIPv4()
{
    StopCapture();
}

// パケットコールバック設定
void PacketCaptureIPv4::SetPacketCallback(std::function<void(const PacketInfo&)> callback)
{
    m_callback = callback;
}

// npcap初期化
bool PacketCaptureIPv4::InitializePcap(const std::wstring& targetIP)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_FINDALLDEVS_FAILED));
        return false;
    }

    // IPv4対応インターフェースを選択
    pcap_if_t* selected = nullptr;
    if (!targetIP.empty()) {
        // targetIPが指定されている場合、そのIPを持つインターフェースのみ選択
        char ipStr[INET_ADDRSTRLEN] = {0};
        size_t converted = 0;
        wcstombs_s(&converted, ipStr, targetIP.c_str(), _TRUNCATE);
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            for (pcap_addr_t* a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(a->addr);
                    char devIpStr[INET_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET, &(sin->sin_addr), devIpStr, INET_ADDRSTRLEN);
                    if (strcmp(ipStr, devIpStr) == 0) {
                        selected = d;
                        break;
                    }
                }
            }
            if (selected) break;
        }
    } else {
        // IP指定なしの場合は最初のIPv4インターフェース
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            for (pcap_addr_t* a = d->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    selected = d;
                    break;
                }
            }
            if (selected) break;
        }
    }

    if (!selected) {
        LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_NO_IPV4_INTERFACE));
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

    LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_PCAP_INITIALIZED_IPV4));
    pcap_freealldevs(alldevs);
    return true;
}

// フィルタ設定
bool PacketCaptureIPv4::SetPcapFilter(const std::wstring& targetIP)
{
    std::string filter;
    if (!targetIP.empty()) {
        char ipStr[INET_ADDRSTRLEN] = {0};
        size_t converted = 0;
        wcstombs_s(&converted, ipStr, targetIP.c_str(), _TRUNCATE);
        filter = "ip and (src host " + std::string(ipStr) + " or dst host " + std::string(ipStr) + ")";
    } else {
        filter = "ip";
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
bool PacketCaptureIPv4::StartCapture(USHORT targetPort, const std::wstring& targetIP)
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
    m_captureThread = std::thread(&PacketCaptureIPv4::CaptureThread, this);

    std::wstring msg = UIHelper::LoadStringFromResource(IDS_CAPTURE_STARTED_IPV4);
    LogWindow::GetInstance().AddLog(msg);
    NetworkLogger::GetInstance().LogRequest(msg, L"CAPTURE_IPv4");
    return true;
}

// キャプチャ停止
void PacketCaptureIPv4::StopCapture()
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

    NetworkLogger::GetInstance().LogRequest(UIHelper::LoadStringFromResource(IDS_CAPTURE_STOPPED_IPV4), L"CAPTURE_IPv4");
    LogWindow::GetInstance().AddLog(UIHelper::LoadStringFromResource(IDS_CAPTURE_STOPPED_IPV4));
}

// キャプチャ中か判定
bool PacketCaptureIPv4::IsCapturing() const
{
    return m_isCapturing;
}

// キャプチャスレッド
void PacketCaptureIPv4::CaptureThread()
{
    WCHAR msg[256];
    swprintf_s(msg, UIHelper::LoadStringFromResource(IDS_CAPTURE_THREAD_STARTED).c_str(), m_targetPort);
    LogWindow::GetInstance().AddLogThreadSafe(msg);

    // 修正: pcap_loopのコールバックでparamにthisを渡す
    int res = pcap_loop(
        m_pcapHandle,
        0,
        [](u_char* param, const pcap_pkthdr* header, const u_char* pkt_data) {
            // paramはthisポインタ
            auto* self = reinterpret_cast<PacketCaptureIPv4*>(param);
            if (self) {
                self->PacketHandler(param, header, pkt_data);
            }
        },
        reinterpret_cast<u_char*>(this)); // paramにthisを渡す

    swprintf_s(msg, UIHelper::LoadStringFromResource(IDS_CAPTURE_THREAD_ENDED).c_str(), res);
    LogWindow::GetInstance().AddLogThreadSafe(msg);
}

// staticメンバー関数として定義
void PacketCaptureIPv4::PacketHandler(u_char* param, const pcap_pkthdr* header, const u_char* pkt_data)
{
    auto* self = reinterpret_cast<PacketCaptureIPv4*>(param);
    if (!self->m_isCapturing) return;

    // デフォルトはEthernetヘッダ(14バイト)をスキップ
    int l2HeaderSize = sizeof(eth_header);

    // ループバックインターフェースの場合はヘッダサイズが異なる
    // WindowsのNpcapループバックはEthernetヘッダなしで4バイトのAFフィールドのみ
    // Linuxのloは通常14バイトのダミーEthernetヘッダ
    // ここではAFフィールド(4バイト)を考慮
    // pcap_datalinkでDLT_NULL(=0)なら4バイト、DLT_EN10MB(=1)なら14バイト
    int datalink = pcap_datalink(self->m_pcapHandle);
    if (datalink == DLT_NULL) {
        l2HeaderSize = 4;
    } else if (datalink == DLT_EN10MB) {
        l2HeaderSize = 14;
    } // 他の型は必要に応じて追加

    if (header->caplen <= static_cast<unsigned int>(l2HeaderSize)) return;

    const BYTE* ipPacket = pkt_data + l2HeaderSize;
    DWORD ipPacketLen = header->caplen - l2HeaderSize;

    // IPヘッダ長チェック
    if (ipPacketLen < sizeof(IPHeader)) return;

    const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(ipPacket);
    DWORD ipHeaderLen = ipHeader->headerLen * 4;
    if (ipHeaderLen < 20 || ipHeaderLen > ipPacketLen) return;

    const BYTE* l4Header = ipPacket + ipHeaderLen;
    DWORD l4Len = ipPacketLen - ipHeaderLen;

    switch (ipHeader->protocol)
    {
    case 6: // TCP
        if (l4Len < sizeof(TCPHeader)) return;
        self->ParseTCPPacket(ipPacket, ipHeaderLen, l4Header, l4Len);
        break;
    case 17: // UDP
        if (l4Len < sizeof(UDPHeader)) return;
        self->ParseUDPPacket(ipPacket, ipHeaderLen, l4Header, l4Len);
        break;
    default:
        break;
    }
}

std::string PacketCaptureIPv4::IPToString(DWORD ip)
{
    struct in_addr addr {};
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

    // 0.0.0.0, 255.255.255.255, 127.x.x.x などは除外（127.0.0.1は例外）
    unsigned long addr = ntohl(sa4.sin_addr.s_addr);
    if ((addr == 0 || addr == 0xFFFFFFFF || (addr >> 24) == 127)&&(addr != 0x7f000001))
        return false;

    return true;
}