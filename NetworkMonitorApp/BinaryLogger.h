#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <mutex>
#include "PacketInfo.h"
#include <Windows.h>

// バイナリログのパケットエントリヘッダー
#pragma pack(push, 1)
struct PacketEntryHeader
{
    UINT64 timestamp;      // タイムスタンプ（FILETIME形式）
    UINT32 sourceIP;       // 送信元IPアドレス
    UINT32 destIP;         // 宛先IPアドレス
    UINT16 sourcePort;     // 送信元ポート
    UINT16 destPort;       // 宛先ポート
    UINT8  protocol;       // プロトコル（6=TCP, 17=UDP）
    UINT8  reserved1;      // 予約（アライメント用）
    UINT16 reserved2;      // 予約（アライメント用）
    UINT32 dataSize;       // データサイズ
};
#pragma pack(pop)

class BinaryLogger
{
public:
    static BinaryLogger& GetInstance();
    
    bool StartLogging(const std::wstring& baseDirectory);
    void StopLogging();
    void LogPacket(const PacketInfo& packet);
    
    bool IsLogging() const { return m_isLogging; }
    UINT64 GetTotalPackets() const { return m_totalPackets; }
    UINT64 GetTotalBytes() const { return m_totalBytes; }
    
    // ログファイルパスの設定と取得
    void SetLogFilePath(const std::wstring& filePath);
    std::wstring GetLogFilePath() const;
    std::wstring GetLogDirectory() const;

private:
    BinaryLogger();
    ~BinaryLogger();
    BinaryLogger(const BinaryLogger&) = delete;
    BinaryLogger& operator=(const BinaryLogger&) = delete;
    
    std::wstring GeneratePacketFileName(const std::wstring& baseDirectory, const SYSTEMTIME& timestamp, UINT64 packetNumber);
    UINT32 IPStringToUInt32(const std::string& ipStr);

    UINT64 SystemTimeToFileTime(const SYSTEMTIME& st);
    
    bool m_isLogging;
    std::wstring m_baseDirectory;
    std::wstring m_logFilePath;    // 追加: ログファイルパス
    UINT64 m_totalPackets;
    UINT64 m_totalBytes;
    UINT64 m_packetCounter;
    mutable std::mutex m_mutex;    // 追加: スレッドセーフのためのミューテックス
};