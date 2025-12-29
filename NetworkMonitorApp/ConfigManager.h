#pragma once
#include <Windows.h>
#include <string>

class ConfigManager
{
public:
    static ConfigManager& GetInstance();
    
    // ポート番号の保存と読み込み
    bool SaveLastPort(USHORT port);
    USHORT LoadLastPort() const;
    
    // 設定ファイルのパス取得
    std::wstring GetConfigFilePath() const;

private:
    ConfigManager() = default;
    ~ConfigManager() = default;
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    
    static constexpr USHORT DEFAULT_PORT = 8080;
    static constexpr wchar_t CONFIG_FILENAME[] = L"NetworkMonitor.ini";
    static constexpr wchar_t SECTION_NAME[] = L"Settings";
    static constexpr wchar_t KEY_LAST_PORT[] = L"LastPort";
};