#include "framework.h"
#include "ConfigManager.h"
#include "AppConstants.h"
#include <shlobj.h>
#include <sstream>

ConfigManager& ConfigManager::GetInstance()
{
    static ConfigManager instance;
    return instance;
}

std::wstring ConfigManager::GetConfigFilePath() const
{
    WCHAR appDataPath[MAX_PATH];
    
    // ユーザーのAppDataフォルダを取得
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath)))
    {
        std::wstring configPath = appDataPath;
        configPath += L"\\NetworkMonitor";
        
        // ディレクトリが存在しない場合は作成
        CreateDirectoryW(configPath.c_str(), nullptr);
        
        configPath += L"\\";
        configPath += CONFIG_FILENAME;
        
        return configPath;
    }
    
    // AppDataが取得できない場合は実行ファイルと同じ場所
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    std::wstring path = exePath;
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
    {
        path = path.substr(0, pos + 1);
    }
    path += CONFIG_FILENAME;
    
    return path;
}

bool ConfigManager::SaveLastPort(USHORT port)
{
    if (port < AppConstants::MIN_PORT || port > AppConstants::MAX_PORT)
    {
        return false;
    }
    
    std::wstring configPath = GetConfigFilePath();
    std::wstring portStr = std::to_wstring(port);
    
    return WritePrivateProfileStringW(
        SECTION_NAME,
        KEY_LAST_PORT,
        portStr.c_str(),
        configPath.c_str()
    ) != 0;
}

USHORT ConfigManager::LoadLastPort() const
{
    std::wstring configPath = GetConfigFilePath();
    
    UINT port = GetPrivateProfileIntW(
        SECTION_NAME,
        KEY_LAST_PORT,
        DEFAULT_PORT,
        configPath.c_str()
    );
    
    // ポート番号の妥当性チェック
    if (port < AppConstants::MIN_PORT || port > AppConstants::MAX_PORT)
    {
        return DEFAULT_PORT;
    }
    
    return static_cast<USHORT>(port);
}