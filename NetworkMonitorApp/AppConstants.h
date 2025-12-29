#pragma once
#include <Windows.h>

namespace AppConstants
{
    // カスタムウィンドウメッセージ
    constexpr UINT WM_PACKET_CAPTURED = WM_USER + 1;
    
    // 文字列バッファサイズ
    constexpr int MAX_STRING_LENGTH = 512;
    constexpr int MAX_PORT_STRING_LENGTH = 10;
    
    // ポート番号の範囲
    constexpr USHORT MIN_PORT = 1;
    constexpr USHORT MAX_PORT = 65535;
    constexpr USHORT DEFAULT_PORT = 8080;
}