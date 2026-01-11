#include "framework.h"
#include "BinaryLogger.h"
#include <sstream>
#include <mutex>
#include <iomanip>
#include <string>
#include <Windows.h>
#include "PacketInfo.h"
#include <fstream>
#include <cstdio>

BinaryLogger& BinaryLogger::GetInstance()
{
    static BinaryLogger instance;
    return instance;
}

BinaryLogger::BinaryLogger()
    : m_isLogging(false)
    , m_totalPackets(0)
    , m_totalBytes(0)
    , m_packetCounter(0)
    , m_logFilePath(L"")
{
}

BinaryLogger::~BinaryLogger()
{
    StopLogging();
}

void BinaryLogger::SetLogFilePath(const std::wstring& filePath)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logFilePath = filePath;
}

std::wstring BinaryLogger::GetLogFilePath() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_logFilePath;
}



std::wstring BinaryLogger::GeneratePacketFileName(const std::wstring& baseDirectory, const SYSTEMTIME& timestamp, UINT64 packetNumber)
{
    std::wostringstream oss;
    oss << baseDirectory;
    
    // ディレクトリパスの最後に \ がない場合は追加
    if (!baseDirectory.empty() && baseDirectory.back() != L'\\' && baseDirectory.back() != L'/')
    {
        oss << L"\\";
    }
    
    // ファイル名: packet_YYYYMMDD_HHMMSS.fff_連番.bin
    oss << L"packet_"
        << std::setfill(L'0')
        << std::setw(4) << timestamp.wYear
        << std::setw(2) << timestamp.wMonth
        << std::setw(2) << timestamp.wDay
        << L"_"
        << std::setw(2) << timestamp.wHour
        << std::setw(2) << timestamp.wMinute
        << std::setw(2) << timestamp.wSecond
        << L"."
        << std::setw(3) << timestamp.wMilliseconds
        << L"_"
        << std::setw(6) << packetNumber
        << L".bin";
    
    return oss.str();
}

bool BinaryLogger::StartLogging(const std::wstring& baseDirectory)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_isLogging)
    {
        return false;
    }
    
    // ベースディレクトリが存在するか確認
    DWORD attrib = GetFileAttributesW(baseDirectory.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES)
    {
        // ディレクトリが存在しない場合は作成
        if (!CreateDirectoryW(baseDirectory.c_str(), NULL))
        {
            DWORD error = GetLastError();
            if (error != ERROR_ALREADY_EXISTS)
            {
                return false;
            }
        }
    }
    else if (!(attrib & FILE_ATTRIBUTE_DIRECTORY))
    {
        // パスがディレクトリではない
        return false;
    }
    
    m_baseDirectory = baseDirectory;
    m_isLogging = true;
    m_totalPackets = 0;
    m_totalBytes = 0;
    m_packetCounter = 0;
    
    return true;
}

void BinaryLogger::StopLogging()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_isLogging)
    {
        m_isLogging = false;
        m_baseDirectory.clear();
    }
}

void BinaryLogger::LogPacket(const PacketInfo& packet)
{
    if (!m_isLogging)
    {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // パケットごとに一意のファイル名を生成
    std::wstring packetFilePath = GeneratePacketFileName(m_baseDirectory, packet.timestamp, m_packetCounter);
    
    // ファイルを開く
    std::ofstream logFile(packetFilePath, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!logFile.is_open())
    {
        // ファイルが開けない場合、ログを記録（デバッグ用）
        WCHAR debugMsg[512];
        swprintf_s(debugMsg, L"Failed to create binary log file: %s\n", packetFilePath.c_str());
        OutputDebugStringW(debugMsg);
        return;
    }
    
    PacketEntryHeader entryHeader = {0};
    entryHeader.timestamp = SystemTimeToFileTime(packet.timestamp);
    entryHeader.sourceIP = IPStringToUInt32(packet.sourceIP);
    entryHeader.destIP = IPStringToUInt32(packet.destIP);
    entryHeader.sourcePort = packet.sourcePort;
    entryHeader.destPort = packet.destPort;
    
    // プロトコルの判定
    if (packet.protocol == "TCP")
    {
        entryHeader.protocol = 6;
    }
    else if (packet.protocol == "UDP")
    {
        entryHeader.protocol = 17;
    }
    else
    {
        entryHeader.protocol = 0;
    }
    
    entryHeader.dataSize = static_cast<UINT32>(packet.data.size());
    
    // ヘッダーの書き込み
    logFile.write(reinterpret_cast<const char*>(&entryHeader), sizeof(entryHeader));
    
    // データの書き込み
    if (entryHeader.dataSize > 0)
    {
        logFile.write(reinterpret_cast<const char*>(packet.data.data()), entryHeader.dataSize);
    }
    
    bool writeSuccess = logFile.good();
    logFile.close();
    
    if (writeSuccess)
    {
        m_packetCounter++;
        m_totalPackets++;
        m_totalBytes += entryHeader.dataSize;
        
        // デバッグログ（最初の数パケットのみ）
        if (m_packetCounter <= 5)
        {
            WCHAR debugMsg[512];
            swprintf_s(debugMsg, L"Binary log created: %s (Packet #%llu)\n", 
                      packetFilePath.c_str(), m_packetCounter);
            OutputDebugStringW(debugMsg);
        }
    }
}

UINT32 BinaryLogger::IPStringToUInt32(const std::string& ipStr)
{
    UINT32 result = 0;
    int parts[4] = {0};
    
    if (sscanf_s(ipStr.c_str(), "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]) == 4)
    {
        result = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    }
    
    return result;
}

UINT64 BinaryLogger::SystemTimeToFileTime(const SYSTEMTIME& st)
{
    FILETIME ft;
    ::SystemTimeToFileTime(&st, &ft);
    return (static_cast<UINT64>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

std::wstring BinaryLogger::GetLogDirectory() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_baseDirectory;
}