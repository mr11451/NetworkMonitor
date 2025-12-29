#pragma once
#include <string>
#include <vector>
#include <Windows.h>

// パケット情報構造体
struct PacketInfo
{
    std::string sourceIP;
    std::string destIP;
    USHORT sourcePort = 0;
    USHORT destPort = 0;
    std::string protocol;
    DWORD dataSize = 0;
    std::vector<BYTE> data;
    SYSTEMTIME timestamp = { 0 };
    bool isIPv6 = false;
};