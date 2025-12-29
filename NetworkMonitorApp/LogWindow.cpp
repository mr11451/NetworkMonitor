#include "framework.h"
#include "LogWindow.h"
#include "resource.h"
#include "WindowPositionManager.h"
#include "AppController.h"
#include <shellapi.h>
#include <shlobj.h>

// レジストリキー定数
namespace
{
    constexpr const wchar_t* LOG_WINDOW_REGISTRY_KEY = L"Software\\NetworkMonitor\\LogWindow";
}

// グローバルヘルパー関数
std::wstring LogWindow::LoadStringFromResource(UINT stringID)
{
    WCHAR buffer[512];
    if (LoadStringW(GetModuleHandle(nullptr), stringID, buffer, 512) > 0)
    {
        return buffer;
    }
    return L"";
}

// レジストリキーの取得
const wchar_t* LogWindow::GetRegistryKey()
{
    return LOG_WINDOW_REGISTRY_KEY;
}

// コンストラクタ・デストラクタ
LogWindow::LogWindow()
    : m_hWnd(nullptr)
    , m_hListBox(nullptr)
    , m_hClearButton(nullptr)
    , m_hLogPathLabel(nullptr)
    , m_hOpenFolderButton(nullptr)
{
}

LogWindow::~LogWindow()
{
    if (m_hWnd)
    {
        WindowPositionManager::SavePosition(m_hWnd, LOG_WINDOW_REGISTRY_KEY);
        DestroyWindow(m_hWnd);
    }
}

// シングルトンインスタンス
LogWindow& LogWindow::GetInstance()
{
    static LogWindow instance;
    return instance;
}
