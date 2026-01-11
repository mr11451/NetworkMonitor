#pragma once

#include <windows.h>

// 共通プロトコルヘッダー構造体
#pragma pack(push, 1)

// Ethernetヘッダ
struct eth_header {
    BYTE dest[6];
    BYTE src[6];
    USHORT type;
};

// TCPヘッダー (IPv4/IPv6共通)
struct TCPHeader
{
    USHORT sourcePort;
    USHORT destPort;
    DWORD seqNum;
    DWORD ackNum;
    BYTE reserved : 4;
    BYTE dataOffset : 4;
    BYTE flags;
    USHORT window;
    USHORT checksum;
    USHORT urgentPtr;
};

// UDPヘッダー (IPv4/IPv6共通)
struct UDPHeader
{
    USHORT sourcePort;
    USHORT destPort;
    USHORT length;
    USHORT checksum;
};

// IPv4ヘッダー
struct IPHeader
{
    BYTE  headerLen : 4;
    BYTE  version : 4;
    BYTE  tos;
    USHORT totalLen;
    USHORT id;
    USHORT fragOffset;
    BYTE  ttl;
    BYTE  protocol;
    USHORT checksum;
    DWORD sourceIP;
    DWORD destIP;
};

// IPv6ヘッダー
struct IPv6Header
{
    BYTE  trafficClassHigh : 4;
    BYTE  version : 4;
    BYTE  flowLabelHigh : 4;
    BYTE  trafficClassLow : 4;
    USHORT flowLabelLow;
    USHORT payloadLength;
    BYTE  nextHeader;
    BYTE  hopLimit;
    BYTE  sourceIP[16];
    BYTE  destIP[16];
};

#pragma pack(pop)