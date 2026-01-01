#pragma once

#include <memory>
#include <functional>
#include "PacketInfo.h"
#include "ProtocolHeaders.h"
#include "PacketCaptureIPv4.h"
#include "PacketCaptureIPv6.h"

// IPv4とIPv6のパケットキャプチャを統合管理するラッパークラス
class PacketCapture
{
public:
    PacketCapture();
    ~PacketCapture();

    // キャプチャ制御
    bool StartCapture(USHORT targetPort, const std::wstring& targetIP);
    void StopCapture();
    bool IsCapturing() const;
    
    // コールバック設定
    void SetPacketCallback(std::function<void(const PacketInfo&)> callback);
    
    // 個別の制御（必要に応じて）
    bool StartIPv4Capture(USHORT targetPort, const std::wstring& targetIP);
    bool StartIPv6Capture(USHORT targetPort, const std::wstring& targetIP);
    void StopIPv4Capture();
    void StopIPv6Capture();
    
    bool IsIPv4Capturing() const;
    bool IsIPv6Capturing() const;

    // IPアドレス指定でのキャプチャ開始（IPv4のみ、IPv6のみ、または両方）
    enum class CaptureMode
    {
        Both,       // IPv4とIPv6両方
        IPv4Only,   // IPv4のみ
        IPv6Only    // IPv6のみ
    };

    bool IsValidIPAddress(const std::wstring& ip, CaptureMode mode);
    bool StartCaptureWithMode(USHORT targetPort, const std::wstring& targetIP, CaptureMode mode);

private:
    std::unique_ptr<PacketCaptureIPv4> m_ipv4Capture;
    std::unique_ptr<PacketCaptureIPv6> m_ipv6Capture;
    std::function<void(const PacketInfo&)> m_callback;
};