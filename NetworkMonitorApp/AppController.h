#pragma once
#include "NetworkMonitor.h"
#include "PacketCapture.h"
#include <memory>
#include <string>
#include <atomic>
#include <mutex>

class AppController
{
public:
    static AppController& GetInstance();
    
    bool Initialize(HWND hMainDlg);
    void Cleanup();
    
    bool StartCapture(HWND hDlg, USHORT port);
    void StopCapture(HWND hDlg);
    
    bool StartBinaryLogging(HWND hDlg, const std::wstring& directoryPath);
    void StopBinaryLogging();
    bool IsBinaryLogging() const;
    
    // テキストログ用メソッドを追加
    bool StartTextLogging(HWND hDlg, const std::wstring& filePath);
    void StopTextLogging();
    bool IsTextLogging() const;
    
    bool IsCapturing() const;
    UINT64 GetPacketCount() const { return m_packetCount; }
    void IncrementPacketCount();
    
    std::wstring GetDefaultBinaryLogPath() const;
    std::wstring GetDefaultTextLogPath() const;
    void SetLogDirectory(const std::wstring& directory);
    std::wstring GetLogDirectory() const;
    std::wstring GetDefaultLogFolderPath() const;
    
    void OnSelectLogFolder(HWND hDlg);
    void OpenSaveLocation(HWND hDlg);
    
private:
    AppController() = default;
    ~AppController() = default;
    AppController(const AppController&) = delete;
    AppController& operator=(const AppController&) = delete;

    void OnPacketCaptured(const PacketInfo& packet);
    
    std::wstring GenerateUniqueLogFileName(const std::wstring& directory) const;
    void WriteTextLog(const std::wstring& logText);

    std::unique_ptr<NetworkMonitor> m_pNetworkMonitor;
    std::unique_ptr<PacketCapture> m_pPacketCapture;
    HWND m_hMainDlg = nullptr;
    std::atomic<UINT64> m_packetCount{0};
    std::wstring m_logDirectory;
    std::wstring m_logFolderPath;
    
    // テキストログ用メンバー変数（ファイルストリームは削除）
    std::wstring m_textLogFilePath;
    mutable std::mutex m_textLogMutex;
    bool m_isTextLogging = false;
    
    void LoadLogFolderPath();
    void SaveLogFolderPath(const std::wstring& path);
};