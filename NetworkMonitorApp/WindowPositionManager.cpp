#include "framework.h"
#include "WindowPositionManager.h"
#include <string>

void WindowPositionManager::SavePosition(HWND hWnd, const std::wstring& registryKey)
{
    if (!hWnd || !IsWindow(hWnd))
        return;

    WINDOWPLACEMENT wp = {};
    wp.length = sizeof(WINDOWPLACEMENT);
    
    if (!GetWindowPlacement(hWnd, &wp))
        return;

    HKEY hKey = nullptr;
    LONG result = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        registryKey.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        nullptr,
        &hKey,
        nullptr
    );

    if (result != ERROR_SUCCESS)
        return;

    // LONG型の値をDWORD型として保存
    DWORD left = static_cast<DWORD>(wp.rcNormalPosition.left);
    DWORD top = static_cast<DWORD>(wp.rcNormalPosition.top);
    DWORD right = static_cast<DWORD>(wp.rcNormalPosition.right);
    DWORD bottom = static_cast<DWORD>(wp.rcNormalPosition.bottom);

    RegSetValueExW(hKey, L"Left", 0, REG_DWORD, 
                   reinterpret_cast<const BYTE*>(&left), sizeof(DWORD));
    RegSetValueExW(hKey, L"Top", 0, REG_DWORD, 
                   reinterpret_cast<const BYTE*>(&top), sizeof(DWORD));
    RegSetValueExW(hKey, L"Right", 0, REG_DWORD, 
                   reinterpret_cast<const BYTE*>(&right), sizeof(DWORD));
    RegSetValueExW(hKey, L"Bottom", 0, REG_DWORD, 
                   reinterpret_cast<const BYTE*>(&bottom), sizeof(DWORD));

    RegCloseKey(hKey);
}

void WindowPositionManager::LoadPosition(HWND hWnd, const std::wstring& registryKey)
{
    if (!hWnd || !IsWindow(hWnd))
        return;

    HKEY hKey = nullptr;
    LONG result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        registryKey.c_str(),
        0,
        KEY_READ,
        &hKey
    );

    if (result != ERROR_SUCCESS)
        return;

    DWORD left = 0, top = 0, right = 0, bottom = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = REG_DWORD;

    bool success = 
        (RegQueryValueExW(hKey, L"Left", nullptr, &type, reinterpret_cast<LPBYTE>(&left), &size) == ERROR_SUCCESS) &&
        (RegQueryValueExW(hKey, L"Top", nullptr, &type, reinterpret_cast<LPBYTE>(&top), &size) == ERROR_SUCCESS) &&
        (RegQueryValueExW(hKey, L"Right", nullptr, &type, reinterpret_cast<LPBYTE>(&right), &size) == ERROR_SUCCESS) &&
        (RegQueryValueExW(hKey, L"Bottom", nullptr, &type, reinterpret_cast<LPBYTE>(&bottom), &size) == ERROR_SUCCESS);

    RegCloseKey(hKey);

    if (!success)
        return;

    // DWORD値をint型に変換
    int x = static_cast<int>(left);
    int y = static_cast<int>(top);
    int width = static_cast<int>(right - left);
    int height = static_cast<int>(bottom - top);

    // 位置が有効かチェック（このメソッドはprivateで定義されているので呼び出せます）
    if (IsPositionValid(x, y, width, height))
    {
        SetWindowPos(hWnd, nullptr, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
    }
}

bool WindowPositionManager::IsPositionValid(int x, int y, int width, int height)
{
    // ウィンドウサイズの妥当性チェック
    if (width <= 0 || height <= 0)
        return false;

    RECT windowRect = { x, y, x + width, y + height };

    // マルチモニター対応
    HMONITOR hMonitor = MonitorFromRect(&windowRect, MONITOR_DEFAULTTONULL);

    if (hMonitor == nullptr)
        return false;

    MONITORINFO mi = {};
    mi.cbSize = sizeof(MONITORINFO);

    if (!GetMonitorInfo(hMonitor, &mi))
        return false;

    RECT intersection = {};
    if (!IntersectRect(&intersection, &windowRect, &mi.rcWork))
        return false;

    int intersectWidth = intersection.right - intersection.left;
    int intersectHeight = intersection.bottom - intersection.top;

    // ウィンドウの50%以上が見えていることを確認
    return (intersectWidth >= width / 2) && (intersectHeight >= height / 2);
}