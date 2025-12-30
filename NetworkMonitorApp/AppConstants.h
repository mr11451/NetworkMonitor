#pragma once

#include <windows.h>

namespace AppConstants
{
    // カスタムメッセージ
    constexpr UINT WM_PACKET_CAPTURED = WM_USER + 1;
    
    // バッファサイズ
    constexpr int MAX_STRING_LENGTH = 512;
    
    // デフォルト値
    namespace Defaults
    {
        constexpr USHORT PORT = 8080;
        constexpr int MAX_LOG_LINES = 1000;
    }
    
    // レジストリキー
    namespace Registry
    {
        constexpr const wchar_t* ROOT_KEY = L"Software\\NetworkMonitor";
        constexpr const wchar_t* MAIN_WINDOW = L"Software\\NetworkMonitor\\MainWindow";
        constexpr const wchar_t* LOG_WINDOW = L"Software\\NetworkMonitor\\LogWindow";
    }
    
    // パケットキャプチャ定数
    namespace Capture
    {
        constexpr int RECV_BUFFER_SIZE = 65536;      // 64KB
        constexpr int SOCKET_BUFFER_SIZE = 262144;   // 256KB
        constexpr DWORD RECV_TIMEOUT_MS = 5000;      // 5秒
    }

    // ポート番号の範囲
    inline constexpr USHORT MIN_PORT = 1;
    inline constexpr USHORT MAX_PORT = 65535;
}