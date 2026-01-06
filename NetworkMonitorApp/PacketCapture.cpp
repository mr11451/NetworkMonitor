#include "framework.h"
#include "PacketCapture.h"
#include "NetworkLogger.h"
#include "LogWindow.h"
#include "UIHelper.h"
#include "Resource.h"
#include "PacketCaptureIPv4.h"
#include "PacketCaptureIPv6.h"

PacketCapture::PacketCapture()
    : m_ipv4Capture(std::make_unique<PacketCaptureIPv4>())
    , m_ipv6Capture(std::make_unique<PacketCaptureIPv6>())
{
}

PacketCapture::~PacketCapture()
{
    StopCapture();
}

void PacketCapture::SetPacketCallback(std::function<void(const PacketInfo&)> callback)
{
    m_callback = callback;
    
    // 両方のキャプチャインスタンスにコールバックを設定
    if (m_ipv4Capture)
    {
        m_ipv4Capture->SetPacketCallback(callback);
    }
    
    if (m_ipv6Capture)
    {
        m_ipv6Capture->SetPacketCallback(callback);
    }
}

bool PacketCapture::StartCapture(USHORT targetPort, const std::wstring& targetIP)
{
    // デフォルトは両方起動
    return StartCaptureWithMode(targetPort, targetIP, CaptureMode::Both);
}

bool PacketCapture::StartCaptureWithMode(USHORT targetPort, const std::wstring& targetIP, CaptureMode mode)
{
    bool ipv4Success = false;
    bool ipv6Success = false;
    
    // IPv4キャプチャ開始
    if (mode == CaptureMode::Both || mode == CaptureMode::IPv4Only)
    {
        if (m_ipv4Capture)
        {
            ipv4Success = m_ipv4Capture->StartCapture(targetPort, targetIP);
        }
    }
    
    // IPv6キャプチャ開始
    if (mode == CaptureMode::Both || mode == CaptureMode::IPv6Only)
    {
        if (m_ipv6Capture)
        {
            ipv6Success = m_ipv6Capture->StartCapture(targetPort, targetIP);
        }
    }
    
    // 少なくとも1つが成功すればOK
    if (ipv4Success || ipv6Success)
    {
        WCHAR msg[256];
        if (mode == CaptureMode::IPv4Only)
        {
            swprintf_s(msg, L"Packet capture started on port %u (IPv4 only)", targetPort);
        }
        else if (mode == CaptureMode::IPv6Only)
        {
            swprintf_s(msg, L"Packet capture started on port %u (IPv6 only)", targetPort);
        }
        else
        {
            swprintf_s(msg, L"Packet capture started on port %u (IPv4: %s, IPv6: %s)", 
                      targetPort, 
                      ipv4Success ? L"OK" : L"Failed",
                      ipv6Success ? L"OK" : L"Failed");
        }
        LogWindow::GetInstance().AddLog(msg);
        NetworkLogger::GetInstance().LogRequest(msg, L"CAPTURE");
        return true;
    }
    
    // 全て失敗
    WCHAR errorMsg[256];
    swprintf_s(errorMsg, L"Failed to start packet capture on port %u", targetPort);
    LogWindow::GetInstance().AddLog(errorMsg);
    NetworkLogger::GetInstance().LogError(errorMsg, 0);
    return false;
}

void PacketCapture::StopCapture()
{
    if (m_ipv4Capture)
    {
        m_ipv4Capture->StopCapture();
    }
    
    if (m_ipv6Capture)
    {
        m_ipv6Capture->StopCapture();
    }
    
    if (IsCapturing())
    {
        LogWindow::GetInstance().AddLog(L"Packet capture stopped");
        NetworkLogger::GetInstance().LogRequest(L"Packet capture stopped", L"CAPTURE");
    }
}

bool PacketCapture::IsCapturing() const
{
    bool ipv4Capturing = m_ipv4Capture && m_ipv4Capture->IsCapturing();
    bool ipv6Capturing = m_ipv6Capture && m_ipv6Capture->IsCapturing();
    
    return ipv4Capturing || ipv6Capturing;
}

bool PacketCapture::StartIPv4Capture(USHORT targetPort, const std::wstring& targetIP)
{
    if (!m_ipv4Capture)
    {
        return false;
    }
    
    return m_ipv4Capture->StartCapture(targetPort, targetIP);
}

bool PacketCapture::StartIPv6Capture(USHORT targetPort, const std::wstring& targetIP)
{
    if (!m_ipv6Capture)
    {
        return false;
    }
    
    return m_ipv6Capture->StartCapture(targetPort, targetIP);
}

void PacketCapture::StopIPv4Capture()
{
    if (m_ipv4Capture)
    {
        m_ipv4Capture->StopCapture();
    }
}

void PacketCapture::StopIPv6Capture()
{
    if (m_ipv6Capture)
    {
        m_ipv6Capture->StopCapture();
    }
}

bool PacketCapture::IsIPv4Capturing() const
{
    return m_ipv4Capture && m_ipv4Capture->IsCapturing();
}

bool PacketCapture::IsIPv6Capturing() const
{
    return m_ipv6Capture && m_ipv6Capture->IsCapturing();
}

bool PacketCapture::IsValidIPAddress(const std::wstring& ip, CaptureMode mode)
{
    switch (mode)
    {
    case CaptureMode::IPv4Only:
        // IPv4として有効かつ使用可能
        return PacketCaptureIPv4::IsValidUsableIPAddress(ip);
    case CaptureMode::IPv6Only:
        // IPv6として有効かつ使用可能
        return PacketCaptureIPv6::IsValidUsableIPAddress(ip);
    case CaptureMode::Both:
        if (PacketCaptureIPv4::IsValidUsableIPAddress(ip))
            return true;
        if (PacketCaptureIPv6::IsValidUsableIPAddress(ip))
            return true;
        return false;
    default:
        return false;
    }
}