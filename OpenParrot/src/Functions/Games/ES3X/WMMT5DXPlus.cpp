#include <StdInc.h>
#include "Utility/InitFunction.h"
#include "Functions/Global.h"
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <fstream>
#include "MinHook.h"
#include <Utility/Hooking.Patterns.h>
#include <chrono>
#include <thread>
#include <format>
#include <ctime>

#ifdef _M_AMD64
#pragma optimize("", off)
#pragma comment(lib, "Ws2_32.lib")

extern LPCSTR hookPort;
uintptr_t imageBaseDxp;
static unsigned char hasp_buffer[0xD40];
static bool isFreePlay;
static bool isEventMode2P;
static bool isEventMode4P;
const char *ipaddrdxplus;

// MUST DISABLE IC CARD, FFB MANUALLY N MT5DX+

// FOR FREEPLAY
unsigned char dxpterminalPackage1_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x12, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0xEC, 0x72, 0x00, 0x41
};

unsigned char dxpterminalPackage2_Free[139] = {
	0x01, 0x04, 0x87, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x14, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x42, 0x3A, 0x08, 0x01, 0x10, 0x03, 0x18, 0x02,
	0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38, 0x01, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68, 0x60, 0x70, 0x60, 0x78, 0x60,
	0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90, 0x01, 0x60, 0x98, 0x01, 0x00,
	0xA0, 0x01, 0xE2, 0xBA, 0xAC, 0xD4, 0x05, 0xA8, 0x01, 0x04, 0xB0, 0x01,
	0x24, 0xB8, 0x01, 0x00, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x99, 0x4E, 0xC6, 0x14
};

unsigned char dxpterminalPackage3_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x19, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x89, 0x93, 0x3A, 0x22
};

unsigned char dxpterminalPackage4_Free[139] = {
	0x01, 0x04, 0x87, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x2E, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x42, 0x3A, 0x08, 0x01, 0x10, 0x03, 0x18, 0x02,
	0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38, 0x01, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68, 0x60, 0x70, 0x60, 0x78, 0x60,
	0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90, 0x01, 0x60, 0x98, 0x01, 0x00,
	0xA0, 0x01, 0xF0, 0xBA, 0xAC, 0xD4, 0x05, 0xA8, 0x01, 0x04, 0xB0, 0x01,
	0x24, 0xB8, 0x01, 0x00, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x55, 0x42, 0x47, 0xD5
};

unsigned char dxpterminalPackage5_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x2F, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x9C, 0xC9, 0xE0, 0x73
};

unsigned char dxpterminalPackage6_Free[139] = {
	0x01, 0x04, 0x87, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x6A, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x42, 0x3A, 0x08, 0x01, 0x10, 0x03, 0x18, 0x02,
	0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38, 0x01, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68, 0x60, 0x70, 0x60, 0x78, 0x60,
	0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90, 0x01, 0x60, 0x98, 0x01, 0x00,
	0xA0, 0x01, 0xF1, 0xBA, 0xAC, 0xD4, 0x05, 0xA8, 0x01, 0x04, 0xB0, 0x01,
	0x24, 0xB8, 0x01, 0x00, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x26, 0xB7, 0x89, 0xD0
};

// FOR COIN ENTRY!
unsigned char dxpterminalPackage1_Coin[75] = {
	0x01, 0x04, 0x47, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x0B, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x09,
	0x06, 0x41, 0x0B
};

unsigned char dxpterminalPackage2_Coin[135] = {
	0x01, 0x04, 0x83, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x39, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x42, 0x3A, 0x08, 0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04,
	0x30, 0x00, 0x38, 0x01, 0x40, 0x00, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60,
	0x60, 0x60, 0x68, 0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88,
	0x01, 0x60, 0x90, 0x01, 0x60, 0x98, 0x01, 0x00, 0xA0, 0x01, 0xD5, 0xBE,
	0x8F, 0xD2, 0x05, 0xA8, 0x01, 0x04, 0xB0, 0x01, 0x24, 0xB8, 0x01, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xF5,
	0xF1, 0x0D, 0xB2
};

unsigned char dxpterminalPackage3_Coin[75] = {
	0x01, 0x04, 0x47, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x3A, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x22,
	0x25, 0x31, 0x0D
};

unsigned char dxpterminalPackage4_Coin[135] = {
	0x01, 0x04, 0x83, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x57, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x42, 0x3A, 0x08, 0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04,
	0x30, 0x00, 0x38, 0x01, 0x40, 0x00, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60,
	0x60, 0x60, 0x68, 0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88,
	0x01, 0x60, 0x90, 0x01, 0x60, 0x98, 0x01, 0x00, 0xA0, 0x01, 0xD6, 0xBE,
	0x8F, 0xD2, 0x05, 0xA8, 0x01, 0x04, 0xB0, 0x01, 0x24, 0xB8, 0x01, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xCA,
	0x8B, 0x15, 0xCB
};

unsigned char dxpterminalPackage5_Coin[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x58, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x3E, 0xB1, 0xB7, 0x22
};

unsigned char dxpterminalPackage6_Coin[139] = {
	0x01, 0x04, 0x87, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x77, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x42, 0x3A, 0x08, 0x01, 0x10, 0x03, 0x18, 0x02,
	0x20, 0x02, 0x28, 0x04, 0x30, 0x00, 0x38, 0x01, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68, 0x60, 0x70, 0x60, 0x78, 0x60,
	0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90, 0x01, 0x60, 0x98, 0x01, 0x00,
	0xA0, 0x01, 0xD7, 0xBE, 0x8F, 0xD2, 0x05, 0xA8, 0x01, 0x04, 0xB0, 0x01,
	0x24, 0xB8, 0x01, 0x00, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0xBD, 0x07, 0xCF, 0xDC
};

//Event mode 2P
unsigned char dxpterminalPackage1_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xd1, 0x0b, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08, 
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xc1, 0x96, 0xc9, 0x2e
};

unsigned char dxpterminalPackage2_Event4P[139] = {
	0x01, 0x04, 0x80, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xd2, 0x0b, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x42, 0x3a, 0x08,
	0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38,
	0x01, 0x40, 0x01, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68,
	0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90,
	0x01, 0x60, 0x98, 0x01, 0x00, 0xa0, 0x01, 0xd8, 0xc3, 0xd6, 0xe1, 0x05,
	0xa8, 0x01, 0x04, 0xb0, 0x01, 0x24, 0xb8, 0x01, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x91, 0x74, 0xca, 0x1e

};

unsigned char dxpterminalPackage3_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8d, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x86, 0xb1, 0x27, 0x9e
};

unsigned char dxpterminalPackage4_Event4P[139] = {
	0x01, 0x04, 0x80, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8e, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x42, 0x3a, 0x08,
	0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38,
	0x01, 0x40, 0x01, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68,
	0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90,
	0x01, 0x60, 0x98, 0x01, 0x00, 0xa0, 0x01, 0xd9, 0xc3, 0xd6, 0xe1, 0x05,
	0xa8, 0x01, 0x04, 0xb0, 0x01, 0x24, 0xb8, 0x01, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xc2, 0x11, 0x2a, 0x66

};

unsigned char dxpterminalPackage5_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xc9, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x5d, 0x49, 0x01, 0x1e
};

unsigned char dxpterminalPackage6_Event4P[139] = {
	0x01, 0x04, 0x80, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xca, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x42, 0x3a, 0x08,
	0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38,
	0x01, 0x40, 0x01, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68,
	0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90,
	0x01, 0x60, 0x98, 0x01, 0x00, 0xa0, 0x01, 0xda, 0xc3, 0xd6, 0xe1, 0x05,
	0xa8, 0x01, 0x04, 0xb0, 0x01, 0x24, 0xb8, 0x01, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xd4, 0x80, 0x16, 0xc2
};


//Event mode 2P
unsigned char dxpterminalPackage1_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xfe, 0x0e, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xaf, 0xa1, 0x42, 0x3d
};

unsigned char dxpterminalPackage2_Event2P[139] = {
	0x01, 0x04, 0x80, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xff, 0x0e, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x42, 0x3a, 0x08,
	0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38,
	0x01, 0x40, 0x02, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68,
	0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90,
	0x01, 0x60, 0x98, 0x01, 0x00, 0xa0, 0x01, 0xa7, 0xc2, 0xa5, 0xe1, 0x05,
	0xa8, 0x01, 0x02, 0xb0, 0x01, 0x24, 0xb8, 0x01, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xe8, 0x94, 0x41, 0x46

};

unsigned char dxpterminalPackage3_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x80, 0x0f, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xa3, 0x94, 0x12, 0x9b
};

unsigned char dxpterminalPackage4_Event2P[139] = {
	0x01, 0x04, 0x80, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8d, 0x0f, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x42, 0x3a, 0x08,
	0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38,
	0x01, 0x40, 0x02, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68,
	0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90,
	0x01, 0x60, 0x98, 0x01, 0x00, 0xa0, 0x01, 0xa8, 0xc2, 0xa5, 0xe1, 0x05,
	0xa8, 0x01, 0x02, 0xb0, 0x01, 0x24, 0xb8, 0x01, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x8b, 0x02, 0xdf, 0xad

};

unsigned char dxpterminalPackage5_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8e, 0x0f, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xa3, 0xc2, 0x27, 0x9c
};

unsigned char dxpterminalPackage6_Event2P[139] = {
	0x01, 0x04, 0x80, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xf0, 0x0e, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x42, 0x3a, 0x08,
	0x01, 0x10, 0x03, 0x18, 0x02, 0x20, 0x02, 0x28, 0x04, 0x30, 0x01, 0x38,
	0x01, 0x40, 0x02, 0x48, 0x00, 0x50, 0x02, 0x58, 0x60, 0x60, 0x60, 0x68,
	0x60, 0x70, 0x60, 0x78, 0x60, 0x80, 0x01, 0x60, 0x88, 0x01, 0x60, 0x90,
	0x01, 0x60, 0x98, 0x01, 0x00, 0xa0, 0x01, 0xa6, 0xc2, 0xa5, 0xe1, 0x05,
	0xa8, 0x01, 0x02, 0xb0, 0x01, 0x24, 0xb8, 0x01, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x97, 0xd5, 0x79, 0xa6
};

// If this is set, logging will be enabled
// and debug functions will be included in
// the compilation

#define _DEBUG

#define HASP_STATUS_OK 0
unsigned int hook_hasp_login(int feature_id, void* vendor_code, int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_login");
#endif
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_logout(int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_logout");
#endif
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_encrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_encrypt");
#endif
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_decrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_decrypt");
#endif
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_get_size(int hasp_handle, int hasp_fileid, unsigned int* hasp_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_get_size");
#endif
	*hasp_size = 0xD40; // Max addressable size by the game... absmax is 4k
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_read(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_read");
#endif
	memcpy(buffer, hasp_buffer + offset, length);
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_write(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_write");
#endif
	return HASP_STATUS_OK;
}

// Set system date patch by pockywitch
typedef bool (WINAPI* SETSYSTEMTIME)(SYSTEMTIME* in);
SETSYSTEMTIME pSetSystemTime = NULL;

bool WINAPI Hook_SetSystemTime(SYSTEMTIME* in)
{
	return TRUE;
}

// **** Save Data Filenames ****

// Settings data filename
#define SETTINGS_FILENAME "opensettings.sav"

// Story data filename
#define STORY_FILENAME "openprogress.sav"

// Versus data filename
#define VERSUS_FILENAME "openversus.sav"

// Mileeage data filename
#define MILE_FILENAME "openmileage.sav"

// Folder path for cars
#define CAR_FILEPATH "OpenParrot_Cars"

// **** Data Region Sizes ****

// Settings region load/save size
#define SETTINGS_DATA_SIZE 0x40

// Versus region load/save size
#define VERSUS_DATA_SIZE 0x100

// Story region load/save size
#define STORY_DATA_SIZE 0x2000

// Miles region load/save size
#define MILE_DATA_SIZE 0x8

// Car region load/save size
#define CAR_DATA_SIZE 0xFF

// String File Lengths

// Maximum sticker length (32 bytes, 8 characters)
#define STICKER_LENGTH 0x10

// Maximum title length (16 Characters)
#define TITLE_LENGTH 0x10

// Maximum name length (16 bytes, 5 characters)
#define NAME_LENGTH 0x10

// Pointer Addresses

// Save Data Location Constant
#define SAVE_OFFSET 0x1F7D578

// Settings Data Offset (Within Save Data Region)
#define SETTINGS_OFFSET 0x400

// Story Data Offset (Within Save Data Region)
#define STORY_OFFSET 0x108

// Mile Data Offset (Within Save Data Region)
#define MILE_OFFSET 0x280

// Car Data Offset (Within Save Data Region)
#define CAR_OFFSET 0x268

// *** Unsigned Char (Memory Storage) Objects ***

// Row which is used to end the sticker region
// Without this written to the sticker second row, 
// the sticker does not display.
unsigned char stringTerminator[0x10] = {
	0x0F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

// Car code of the selected car (in the menu)
unsigned char selectedCarCodeDxp;

// *** Char Array (String) Variables ***

// Sticker filename string
char stickerFileNameDxp[FILENAME_MAX];

// Title filename string
char titleFileNameDxp[FILENAME_MAX];

// Car name filename string
char nameFileNameDxp[FILENAME_MAX];

// Car filename string
char carFileNameDxp[FILENAME_MAX];

// *** Boolean Variables ***

// Sets if saving is allowed or not
static bool saveOk = false;

// If custom car is used
bool customCarDxp = false;

// Sets if loading is allowed
bool loadOkDxp = false;

// SaveOk(void): Void
// Enables saving
static int SaveOk()
{
	saveOk = true;
	return 1;
}

// Functions in this are are only used in debug mode

#ifdef _DEBUG
// ******************************************** //
// ************ Development  Tools ************ //
// ******************************************** //

// writeMessage(filename: String, message: String): Int
// Given a filename string and a message string, appends
// the message to the given file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int writeMessage(std::string filename, std::string message, bool timestamp = false, bool newline = false)
{
	// Log file to write to
	std::ofstream eventLog;

	// Open the filename provided (append mode)
	eventLog.open(filename, std::ios_base::app);

	// File open success
	if (eventLog.is_open())
	{
		// If timestamp switch is applied
		if (timestamp)
		{
			// Get the current time
			auto t = std::time(nullptr);
			auto tm = *std::localtime(&t);

			// Add the timestamp to the message
			eventLog << "[" << std::put_time(&tm, "%d-%m-%Y %H-%M-%S") << "] ";
		}

		// Write the message to the file
		eventLog << message;

		// Newline switch applied
		if (newline)
		{
			// Add the newline to the message
			eventLog << "\n";
		}

		// Close the log file handle
		eventLog.close();

		// Success
		return 0;
	}
	else // File open failed
	{
		// Failure
		return 1;
	}
}

// Debugging event log file
static std::string logfile = "wmmt5dxp_errors.txt";

// writeLog(message: String, logLevel: int): Void
// Given a message and a log level, writes a 
static int writeLog(std::string message)
{
	// Write to the log file (with timestamp and newline)
	return writeMessage(logfile, message, true, true);
}

// writeMemory(memory: uintptr_t, value: unsigned char, size: size_t, force: bool): Void
// Given a memory address, a value and a size sets every empty b
static void writeMemory(uintptr_t memory, int value, size_t size, bool force = false)
{
	// Loop until you hit the size specified by the size parameter
	for (int i = 0; i < size; i++)
	{
		// Get the pointer to the current memory address
		uintptr_t ptr = (memory + (i * 0x4));

		// If the force switch is not set
		if (!force)
		{
			// Get the data at the memory address
			unsigned int a = *(uintptr_t*)ptr;

			// If the block is empty
			if (a == 0)
			{
				// Write data to it
				memset((void*)ptr, value, 0x1);
			}
		}
		else // Force switch set
		{
			// Write data to it
			memset((void*)ptr, value, 0x1);
		}
	}
}
#endif

// writeDump(filename: Char*, data: unsigned char *, size: size_t): Int
// Given a filename, a data buffer pointer and a size dumps 'size' data
// from 'data' to the filename provided by 'filename'. This code is used
// for most of the saving routines, and is not just for dev purposes. 
// Returns a status code of 0 if successful, and a code of 1 if failed.
static int writeDump(char* filename, unsigned char* data, size_t size)
{
#ifdef _DEBUG
	writeLog("Call to writeDump...");
#endif

	// Open the file with the provided filename
	FILE* file = fopen(filename, "wb");

	// Success/failure status
	bool status = 1;

	// File opened successfully
	if (file)
	{
		// Write the data to the file
		fwrite((void*)data, 1, size, file);

		// Close the file
		fclose(file);

		// Return success status
		status = 0;
	}

#ifdef _DEBUG
	status ? writeLog("writeDump failed.") : writeLog("writeDump success.");
#endif

	// Return success code
	return status;
}

// dumpMemory(filename: char*, memory: uintptr_t, size: size_t): Void
// Given a filename, a pointer to a position in memory and a size, dumps
// 'size' amount of data from 'memory' and writes it to the file 'filename'.
// Returns a status code of 0 if successful, and a code of 1 if failed.
static int dumpMemory(char* filename, uintptr_t memory, size_t size)
{
#ifdef _DEBUG
	writeLog("Call to dumpMemory...");
#endif

	// Create the array to dump the memory data to
	unsigned char* data = (unsigned char*)malloc(size);

	// Success/failure status
	bool status = 1;

	// If malloc is successful
	if (data)
	{
		// Set all of the pointer data to zero
		memset(data, 0, size);

		// Copy the memory from the source
		memcpy(data, (void*)memory, size);

		// Write the memory to a file
		status = writeDump(filename, data, size);

		// Free the allocated memory
		free(data);
	}

#ifdef _DEBUG
	status ? writeLog("dumpMemory failed.") : writeLog("dumpMemory success.");
#endif

	return status;
}

#ifdef _DEBUG
// Number of seconds to wait between writes
static int dumpMemoryDelay;
static std::string dumpMemoryFolder;
static uintptr_t dumpMemoryAddr;
static size_t dumpMemorySize;

// dumpMemoryThread(pArguments: void*): DWORD WINAPI
static DWORD WINAPI watchMemoryThread(void* pArguments)
{
	writeLog("Call to watchMemoryThread...");

	// File to dump the current memory to
	char path[FILENAME_MAX];

	// Loop counter
	int i = 0;

	// Infinite loop
	while (true)
	{
		// Empty the path string
		memset(path, 0x0, 255);

		// Write the path to the new file to the string
		sprintf(path, "%s\\%i.bin", dumpMemoryFolder.c_str(), i);

		// Dump the contents of the address to the file
		dumpMemory(path, dumpMemoryAddr, dumpMemorySize);

		// Wait for 'delay' number of seconds before dumping again
		std::this_thread::sleep_for(std::chrono::seconds(dumpMemoryDelay));

		// Increment the counter
		i++;
	}

	writeLog("watchMemoryThread done.");
}

// watchMemory(char * filename, uintptr_t memory, size_t size, int delay)
// Given a filename (folder path), memory pointer, size and delay continiously
// dumps 'size' data from memory address 'memory' incrementally to files in 
// the folder 'filename'. Memory will be dumped incrementally every 'delay' seconds.
// Unfortunately due to the reliance on global variables, only one dumpMemoryThread
// can be running at any time.
static void watchMemory(char* filename, uintptr_t memory, size_t size, int delay)
{
	writeLog("Call to watchMemory...");

	// Update the dumpMemoryFolder variable
	dumpMemoryFolder = std::string(filename);

	// Create the path to the folder 'filename'
	std::filesystem::create_directories(dumpMemoryFolder);

	// Update the other global variables for the thread

	dumpMemoryDelay = delay;
	dumpMemoryAddr = memory;
	dumpMemorySize = size;

	// Start the memory dump thread
	CreateThread(0, 0, watchMemoryThread, 0, 0, 0);

	writeLog("watchMemory done.");
}
#endif

#ifdef _DEBUG
static int dumpPointerMemory()
{
	writeLog("Call to dumpPointerMemory...");

	uintptr_t saveOffset = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	/*
	dumpMemory("0x00.bin", *(uintptr_t*)(saveOffset + 0x0), 0x2000);
	dumpMemory("0x08.bin", *(uintptr_t*)(saveOffset + 0x8), 0x2000);
	dumpMemory("0x18.bin", *(uintptr_t*)(saveOffset + 0x18), 0x2000);
	dumpMemory("0x20.bin", *(uintptr_t*)(saveOffset + 0x20), 0x2000);
	dumpMemory("0x30.bin", *(uintptr_t*)(saveOffset + 0x30), 0x2000);
	dumpMemory("0x68.bin", *(uintptr_t*)(saveOffset + 0x68), 0x2000);
	dumpMemory("0xC0.bin", *(uintptr_t*)(saveOffset + 0xC0), 0x2000);
	dumpMemory("0xC8.bin", *(uintptr_t*)(saveOffset + 0xC8), 0x2000);
	dumpMemory("0xD8.bin", *(uintptr_t*)(saveOffset + 0xD8), 0x2000);
	dumpMemory("0xE0.bin", *(uintptr_t*)(saveOffset + 0xE0), 0x2000);
	dumpMemory("0xF0.bin", *(uintptr_t*)(saveOffset + 0xF0), 0x2000);
	dumpMemory("0xF8.bin", *(uintptr_t*)(saveOffset + 0xF8), 0x2000);
	dumpMemory("0x108.bin", *(uintptr_t*)(saveOffset + 0x108), 0x2000);
	dumpMemory("0x110.bin", *(uintptr_t*)(saveOffset + 0x110), 0x2000);
	dumpMemory("0x158.bin", *(uintptr_t*)(saveOffset + 0x158), 0x2000);
	dumpMemory("0x160.bin", *(uintptr_t*)(saveOffset + 0x160), 0x2000);
	dumpMemory("0x170.bin", *(uintptr_t*)(saveOffset + 0x170), 0x2000);
	dumpMemory("0x178.bin", *(uintptr_t*)(saveOffset + 0x178), 0x2000);
	// dumpMemory("0x198.bin", *(uintptr_t*)(saveOffset + 0x198), 0x2000); not a ptr
	dumpMemory("0x1A8.bin", *(uintptr_t*)(saveOffset + 0x1A8), 0x2000);
	dumpMemory("0x1B0.bin", *(uintptr_t*)(saveOffset + 0x1B0), 0x2000);
	dumpMemory("0x218.bin", *(uintptr_t*)(saveOffset + 0x218), 0x2000);
	dumpMemory("0x228.bin", *(uintptr_t*)(saveOffset + 0x228), 0x2000);
	dumpMemory("0x268.bin", *(uintptr_t*)(saveOffset + 0x268), 0x2000);
	dumpMemory("0x288.bin", *(uintptr_t*)(saveOffset + 0x288), 0x2000);
	// dumpMemory("0x2D8.bin", *(uintptr_t*)(saveOffset + 0x2D8), 0x2000);
	dumpMemory("0x400.bin", *(uintptr_t*)(saveOffset + 0x400), 0x2000);
	dumpMemory("0x528.bin", *(uintptr_t*)(saveOffset + 0x528), 0x2000);
	dumpMemory("0x548.bin", *(uintptr_t*)(saveOffset + 0x548), 0x2000);
	dumpMemory("0x568.bin", *(uintptr_t*)(saveOffset + 0x568), 0x2000);
	dumpMemory("0x588.bin", *(uintptr_t*)(saveOffset + 0x588), 0x2000);
	dumpMemory("0x8D0.bin", *(uintptr_t*)(saveOffset + 0x8D0), 0x2000);
	dumpMemory("0x8F8.bin", *(uintptr_t*)(saveOffset + 0x8F8), 0x2000);
	dumpMemory("0xA50.bin", *(uintptr_t*)(saveOffset + 0xA50), 0x2000);

	// Derefence the settings (??) region
	uintptr_t settings = *(uintptr_t*)(saveOffset + 0x400);

	// Write 1s to every blank memory space lol
	// writeMemory(settings + 0x08, 0x2, 0x10);

	watchMemory("settings", settings, 0x100, 15);

	*/

	writeLog("dumpPointerMemory complete.");

	// Return success/fail status
	return 0;
}
#endif

// fixStoryTune(void): Int
// If the chapter 29 fix is enabled, 
// the game will skip chapter 29 and
// the player will rank up to basic
// tuning a story early. This fix
// ensures that the player still
// gets the extra tuning point
// if the fix is applied.
static int fixStoryTune()
{
#ifdef _DEBUG
	writeLog("Call to fixStoryTune...");
#endif

	// Get the memory addresses for the car base save, power and handling values
	auto carSaveBase = (uintptr_t*)(*(uintptr_t*)(imageBaseDxp + SAVE_OFFSET) + CAR_OFFSET);
	auto powerAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase)+0xAC); // Power offset
	auto handleAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase)+0xB8); // Handling offset

	// Dereference the power value from the memory address
	auto powerValue = injector::ReadMemory<uint8_t>(powerAddress, true);
	auto handleValue = injector::ReadMemory<uint8_t>(handleAddress, true);

	// Update code (Default not updated)
	bool update = 1;

	// Check if the power value is less than 10 (basic tune)
	if (powerValue < 0xA)
	{
		// Add one to the power value
		injector::WriteMemory<uint8_t>(powerAddress, (powerValue + 0x1), true);

		// Value has been updated
		update = 0;
	}
	else if (handleValue < 0xA) // Otherwise, if the handling value is less than 10 (basic tune)
	{
		// Add one to the handling value
		injector::WriteMemory<uint8_t>(handleAddress, (handleValue + 0x1), true);

		// Value has been updated
		update = 0;
	}

#ifdef _DEBUG
	update ? writeLog("fixStoryTune not updated.") : writeLog("fixStoryTune updated.");
#endif

	// Return if the value was updated or not
	return update;
}

// setFullTune(void): Int
// If the currently loaded car is NOT fully tuned, 
// updates the power and handling values to be fully
// tuned (16 for each). If they are already fully tuned,
// does not change any values.
static int setFullTune()
{
#ifdef _DEBUG
	writeLog("Call to setFullTune...");
#endif

	// Get the memory addresses for the car base save, power and handling values
	auto carSaveBase = (uintptr_t*)(*(uintptr_t*)(imageBaseDxp + SAVE_OFFSET) + CAR_OFFSET);
	auto powerAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase) + 0xAC); // Power offset
	auto handleAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase) + 0xB8); // Handling offset

	// Dereference the power value from the memory address
	auto powerValue = injector::ReadMemory<uint8_t>(powerAddress, true);
	auto handleValue = injector::ReadMemory<uint8_t>(handleAddress, true);

	// Update code (Default not updated)
	bool update = 1;

	// If the power and handling values do not add up to fully tuned
	if (powerValue + handleValue < 0x20)
	{
		// Car is not fully tuned, force it to the default full tune
		injector::WriteMemory<uint8_t>(powerAddress, 0x10, true);
		injector::WriteMemory<uint8_t>(handleAddress, 0x10, true);

		// Success status
		update = 0;
	}

#ifdef _DEBUG
	update ? writeLog("setFullTune not updated.") : writeLog("setFullTune updated.");
#endif

	// Return update code
	return update;
}

// forceFullTune(pArguments: void*): DWORD WINAPI
// Function which runs in a secondary thread if the forceFullTune
// option is selected in the menu. If the player's car is not fully
// tuned, it is forcibly set to max tune. If the player's car is already
// fully tuned, it is left alone. 
static DWORD WINAPI spamFullTune(void* pArguments)
{
#ifdef _DEBUG
	writeLog("Call to spamFullTune...");
#endif

	// Loops while the program is running
	while (true) {

		// Only runs every 16th frame
		Sleep(16);

		// Run the set full tune process
		setFullTune();
	}

#ifdef _DEBUG
	writeLog("spamFullTune done.");
#endif
}

/*
#ifdef _DEBUG
// Custom aura (2 bytes)
char customAuraDxp[2];

static DWORD WINAPI spamCustomAura(LPVOID)
{
	writeLog("Call to spamCustomAura...");


	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Watch the car memory save region
	watchMemory("car_dump", carSaveBase, 0x100, 15);

	// Infinite loop
	while (true)
	{
		// Wait 50ms
		Sleep(50);

		// Write the custom name to the car name in the name plate
		memcpy((void*)(carSaveBase + 0xF0), customAuraDxp, 0x2);
	}

	writeLog("spamCustomAura done.");

}
#endif
*/

// Custom name (i.e. Scrubbs)
char customNameDxp[256];

static DWORD WINAPI spamCustomName(LPVOID)
{
#ifdef _DEBUG
	writeLog("Call to spamCustomName...");
#endif

	// Infinite loop
	while (true)
	{
		// Wait 50ms
		Sleep(50);

		// Get the address of the car name value in the name plate
		void* value = (void*)(imageBaseDxp + 0x1F846F0);

		// Write the custom name to the car name in the name plate
		memcpy(value, customNameDxp, strlen(customNameDxp) + 1);
	}

#ifdef _DEBUG
	writeLog("spamCustomName done.");
#endif
}

// saveCustomName(filename: char*): Int
// Given a filename, saves the default custom name
// attribute to the file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int saveCustomSticker(char* filename)
{
#ifdef _DEBUG
	writeLog("Call to saveCustomSticker...");
#endif

	// Success status for the custom sticker dump
	bool status = writeDump(filename, stringTerminator, STICKER_LENGTH);

#ifdef _DEBUG
	status ? writeLog("saveCustomSticker failed.") : writeLog("saveCustomSticker success.");
#endif

	// Return status code
	return status;
}

// loadCustomSticker(filename: char*): Int
// Given a filename, loads the custom sticker 
// attribute to the file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int loadCustomSticker(char* filename)
{
#ifdef _DEBUG
	writeLog("Call to loadCustomSticker...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Address where the window sticker is stored
	uintptr_t stickerPtr = *(uintptr_t*)(carSaveBase + 0xC8);

	// Success status (default: Failed to open file)
	int status = 1;

	// Custom title file does not exist
	if (!(FileExists(filename)))
	{
		// Create the default file
		saveCustomSticker(filename);
	}
	else // Custom title file does exist
	{
		// Open the file with the file name
		FILE* file = fopen(filename, "rb");

		// File is opened successfully
		if (file)
		{
			// Get the length of the file
			fseek(file, 0, SEEK_END);
			int fsize = ftell(file);

			// If the file has the right size
			if (fsize == STICKER_LENGTH)
			{
				// Reset to start of the file 
				// and read it into the car 
				// data variable
				fseek(file, 0, SEEK_SET);

				// Sticker string storage
				char sticker[STICKER_LENGTH];

				// Empty the title array
				memset(sticker, 0x0, STICKER_LENGTH);

				// Read the string content from the file
				fread(sticker, 0x1, STICKER_LENGTH, file);

				// Write the new title to the string value
				memcpy((void*)stickerPtr, sticker, STICKER_LENGTH);

				// Write the string end line characters to the second row of the pointer
				memcpy((void*)(stickerPtr + 0x10), stringTerminator, STICKER_LENGTH);

				// Close the file
				fclose(file);

				// Success
				status = 0;
			}
			else // Sticker file is wrong size
			{
				// Incorrect file size 
				status = 2;
			}
		}
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomSticker success.");
		break;
	case 1: // No file
		writeLog("loadCustomSticker failed: No file. Default file created.");
		break;
	case 2: // File wrong size
		writeLog("loadCustomSticker failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadCustomSticker failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

// saveCustomName(filename: char*): Int
// Given a filename, saves the default custom name
// attribute to the file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int saveCustomName(char* filename)
{
#ifdef _DEBUG
	writeLog("Call to saveCustomName...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t namePtr = *(uintptr_t*)(carSaveBase + 0x20);

	// Dump the default name to the file

	// Success status for the custom sticker dump
	bool status = dumpMemory(filename, namePtr, NAME_LENGTH);

#ifdef _DEBUG
	status ? writeLog("saveCustomName failed.") : writeLog("saveCustomName success.");
#endif

	// Return status code
	return status;
}


// loadCustomName(filename: char*): Int
// Given a filename, loads the default custom name
// attribute from the file. If the file does not
// exist, it is created using saveCustomName. 
// Returns true on a successful execution.
static int loadCustomName(char* filename)
{
#ifdef _DEBUG
	writeLog("Call to loadCustomName...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t namePtr = *(uintptr_t*)(carSaveBase + 0x20);

	// Success status (default: Failed to open file)
	int status = 1;

	// Custom title file does not exist
	if (!(FileExists(filename)))
	{
		// Create the default file
		saveCustomName(filename);
	}
	else // Custom name file does not exist
	{
		// Open the file with the file name
		FILE* file = fopen(filename, "rb");

		// File is opened successfully
		if (file)
		{
			// Get the length of the file
			fseek(file, 0, SEEK_END);
			int fsize = ftell(file);

			// If the file has the right size
			if (fsize == NAME_LENGTH)
			{
				// Reset to start of the file 
				// and read it into the car 
				// data variable
				fseek(file, 0, SEEK_SET);

				// Car Name string storage
				char name[NAME_LENGTH];

				// Empty the title array
				memset(name, 0x0, NAME_LENGTH);

				// Read the string content from the file
				fread(name, 0x1, NAME_LENGTH, file);

				// Empty the existing title content
				memset((void*)namePtr, 0x0, NAME_LENGTH);

				// Write the new title to the string value
				memcpy((void*)namePtr, name, NAME_LENGTH);

				// Close the file
				fclose(file);

				// Success
				status = 0;
			}
			else // Name file is the wrong size
			{
				// Incorrect file size
				status = 2;
			}
		}
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomName success.");
		break;
	case 1: // No file
		writeLog("loadCustomName failed: No file. Default file created.");
		break;
	case 2: // File wrong size
		writeLog("loadCustomName failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadCustomName failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

// saveCustomTitle(filepath: char*): Int
// Saves the custom title value to the current car's title, 
// otherwise creates a default title.
static int saveCustomTitle(char* filename)
{
#ifdef _DEBUG
	writeLog("Call to saveCustomTitle...");
#endif

	// Open the file for the title
	FILE* file = fopen(filename, "w+");

	// Status code (Default fail)
	bool status = 1;
	
	// Create the title array
	char title[TITLE_LENGTH];

	// Empty the title array
	memset(title, 0x0, TITLE_LENGTH);

	// Write the default title to the string
	sprintf(title, "Wangan Beginner");

	// File is opened successfully
	if (file)
	{
		// Write the title string to the file
		fwrite((void*)title, 1, TITLE_LENGTH, file);

		// Close the file handle
		fclose(file);

		// Success
		status = 0;
	}

#ifdef _DEBUG
	status ? writeLog("saveCustomTitle failed.") : writeLog("saveCustomTitle success.");
#endif

	// Return status code
	return status;
}

// loadCustomTitle(filepath: char*): Int
// Loads the title string from the title file for the given car.
static int loadCustomTitle(char* filename)
{
#ifdef _DEBUG
	writeLog("Call to loadCustomTitle...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Address where the title is saved
	uintptr_t titlePtr = *(uintptr_t*)(carSaveBase + 0xB0);

	// Success status (default: Failed to open file)
	int status = 1;

	// Custom title file does not exist
	if (!(FileExists(filename)))
	{
		// Save the custom title
		saveCustomTitle(filename);
	}
	else // Custom title file does not exist
	{
		// Open the file with the file name
		FILE* file = fopen(filename, "rb");

		// File is opened successfully
		if (file)
		{
			// Get the length of the file
			fseek(file, 0, SEEK_END);
			int fsize = ftell(file);

			// If the file has the right size
			if (fsize == TITLE_LENGTH)
			{
				// Reset to start of the file 
				// and read it into the car 
				// data variable
				fseek(file, 0, SEEK_SET);

				// Title string storage
				char title[TITLE_LENGTH];

				// Empty the title array
				memset(title, 0x0, TITLE_LENGTH);

				// Read the string content from the file
				fread(title, 0x1, TITLE_LENGTH, file);

				// Empty the existing title content
				memset((void*)titlePtr, 0x0, TITLE_LENGTH);

				// Write the new title to the string value
				memcpy((void*)titlePtr, title, TITLE_LENGTH);

				// Close the file
				fclose(file);

				// Success
				status = 0;
			}
			else // Title file is wrong size
			{
				// Incorrect file size 
				status = 2;
			}
		}
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomTitle success.");
		break;
	case 1: // No file
		writeLog("loadCustomTitle failed: No file. Default file created.");
		break;
	case 2: // File wrong size
		writeLog("loadCustomTitle failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadCustomTitle failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

// loadCarFile(filename: char*): Int
// Given a filename, loads the data from
// the car file into memory. 
static int loadCarFile(char* filename)
{
#ifdef _DEBUG
	writeLog("Call to loadCarFile...");
#endif

	// Car save data reserved memory
	unsigned char carDataDxp[CAR_DATA_SIZE];

	// Car Profile saving
	memset(carDataDxp, 0, CAR_DATA_SIZE);

	// Open the file with the filename
	FILE* file = fopen(filename, "rb");

	// Status code default: Failed to open
	int status = 1;

	// File open OK
	if (file)
	{
		// Get the length of the file
		fseek(file, 0, SEEK_END);
		int fsize = ftell(file);

		// If the file has the right size
		if (fsize == CAR_DATA_SIZE)
		{
			// Reset to start of the file and read it into the car data variable
			fseek(file, 0, SEEK_SET);
			fread(carDataDxp, fsize, 1, file);

			// Address where player save data starts
			uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

			// Address where car save data starts
			uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

			// memcpy((void*)(carSaveBase + 0x00), carDataDxp + 0x00, 8); // Crash (Pointer)
			// memcpy((void*)(carSaveBase + 0x08), carDataDxp + 0x08, 8); // ??
			// memcpy((void*)(carSaveBase + 0x10), carDataDxp + 0x10, 8); // Crash (Pointer)
			// memcpy((void*)(carSaveBase + 0x18), carDataDxp + 0x18, 8); // ??

			// memcpy((void*)(carSaveBase + 0x20), carDataDxp + 0x20, 8); // Crash (Pointer)
			memcpy((void*)(carSaveBase + 0x28), carDataDxp + 0x28, 8); // Region (0x28)
			memcpy((void*)(carSaveBase + 0x30), carDataDxp + 0x30, 8); // CarID (0x34)
			// memcpy((void*)(carSaveBase + 0x38), carDataDxp + 0x38, 4); // Stock Colour (0x38)
			memcpy((void*)(carSaveBase + 0x3C), carDataDxp + 0x3C, 4); // CustomColor (0x3C)

			memcpy((void*)(carSaveBase + 0x40), carDataDxp + 0x40, 8); // Rims (0x40), Rims Colour (0x44)
			memcpy((void*)(carSaveBase + 0x48), carDataDxp + 0x48, 8); // Aero (0x48), Hood (0x4C)
			// memcpy((void*)(carSaveBase + 0x50), carDataDxp + 0x50, 8); // Crash (Pointer)
			memcpy((void*)(carSaveBase + 0x58), carDataDxp + 0x58, 8); // Wing (0x58), Mirror (0x5C)

			memcpy((void*)(carSaveBase + 0x60), carDataDxp + 0x60, 8); // Sticker (0x60), Sticker Type (0x64)
			// memcpy((void*)(carSaveBase + 0x68), carDataDxp + 0x60, 8); // Crash (Pointer)
			memcpy((void*)(carSaveBase + 0x70), carDataDxp + 0x70, 8); // ?? 
			memcpy((void*)(carSaveBase + 0x78), carDataDxp + 0x78, 8); // ?? 

			memcpy((void*)(carSaveBase + 0x80), carDataDxp + 0x80, 8); // ??
			memcpy((void*)(carSaveBase + 0x88), carDataDxp + 0x88, 8); // Roof Sticker (0x88), Roof Sticker Type (0x8C)
			memcpy((void*)(carSaveBase + 0x90), carDataDxp + 0x90, 8); // Neon (0x90), Trunk (0x94)
			memcpy((void*)(carSaveBase + 0x98), carDataDxp + 0x98, 8); // Plate Frame (0x98), 1SP-3SP Frame (0x99-9B), Plate Frame Colour (0x9C) (??)

			memcpy((void*)(carSaveBase + 0xA0), carDataDxp + 0xA0, 8); // Plate Number (0xA0), vinyl_body_challenge_prefecture_1~15 (0xA4)
			memcpy((void*)(carSaveBase + 0xA8), carDataDxp + 0xA8, 8); // vinyl_body_challenge_prefecture (0xA8), Power (0xAC)
			// memcpy((void*)(carSaveBase + 0xB0), carDataDxp + 0xB0, 8); // Crash (Title Pointer) (B0)
			memcpy((void*)(carSaveBase + 0xB8), carDataDxp + 0xB8, 8); // Handling (0xB8), Rank (0xBC)

			// Example for setting license plate number to 4 20:
			// memset((void*)(carSaveBase + 0xA1), 0x01, 0x1);
			// memset((void*)(carSaveBase + 0xA0), 0xA4, 0x1);

			memcpy((void*)(carSaveBase + 0xC0), carDataDxp + 0xC0, 8); // Window Sticker Toggle (0xC0)
			// memcpy((void*)(carSaveBase + 0xC8), carDataDxp + 0xC8, 8); // Crash (Pointer)
			memcpy((void*)(carSaveBase + 0xD0), carDataDxp + 0xD0, 8); // Window Sticker Value (0xD4)
			memcpy((void*)(carSaveBase + 0xD8), carDataDxp + 0xD8, 8); // Versus Market (0xDC)

			// memcpy((void*)(carSaveBase + 0xE0), carDataDxp + 0xE0, 8); // Crash (Pointer)
			// memcpy((void*)(carSaveBase + 0xE8), carDataDxp + 0xE8, 8); // Crash (Pointer)
			memcpy((void*)(carSaveBase + 0xF0), carDataDxp + 0xF0, 8); // ??
			// memcpy((void*)(carSaveBase + 0xF8), carDataDxp + 0xF8, 8); // Crash (Region Pointer) (F8)

/*
#ifdef _DEBUG
			// Clear the aura region
			memset(customAuraDxp, 0x0, 0x2);

			// Copy the aura to the aura save data
			memcpy(customAuraDxp, carDataDxp + 0xF0, 0x2);

			// Create the spam custom aura thread
			CreateThread(0, 0, spamCustomAura, 0, 0, 0);
#endif
*/

			// Success
			status = 0;
		}
		else // Car file is not the correct size
		{
			// Car file incorrect size code
			status = 2;
		}

		// Disable loading
		loadOkDxp = false;

		// Close the file
		fclose(file);
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCarFile success.");
		break;
	case 1: // No file
		writeLog("loadCarFile failed: No file.");
		break;
	case 2: // File wrong size
		writeLog("loadCarFile failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadCarFile failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

// loadCarData(filepath: char*): Void
// Given a filepath, attempts to load a 
// car file (either custom.car or specific
// car file) from that folder.
static int loadCarData(char * filepath)
{
#ifdef _DEBUG
	writeLog("Call to loadCarData...");
#endif

	// Custom car disabled by default
	customCarDxp = false;

	// Car file load success status
	bool status = false;

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\OpenParrot_Cars");
	sprintf(path, "%s\\%s", path, CAR_FILEPATH);

	// Create the OpenParrot_cars directory at the given filepath
	std::filesystem::create_directories(path);

	// Get the path to the custom car file
	sprintf(carFileNameDxp, "%s\\custom.car", path);

	// If the custom car file exists
	if (FileExists(carFileNameDxp))
	{
		// Get the path to the title file
		sprintf(titleFileNameDxp, "%s\\custom.title", path);

		// Get the path to the name file
		sprintf(nameFileNameDxp, "%s\\custom.name", path);

		// Load the custom car file
		status = loadCarFile(carFileNameDxp);

		// Enable custom car switch
		customCarDxp = true;
	}
	else // Custom car file does not exist
	{
		// Empty the car filename string
		memset(carFileNameDxp, 0x0, FILENAME_MAX);

		// Get the path to the specific car file
		sprintf(carFileNameDxp, "%s\\%08X.car", path, selectedCarCodeDxp);

		// Get the path to the name file
		sprintf(nameFileNameDxp, "%s\\%08X.name", path, selectedCarCodeDxp);

		// Get the path to the specific car title file
		sprintf(titleFileNameDxp, "%s\\%08X.title", path, selectedCarCodeDxp);

		// Get the path to the specific car title file
		sprintf(stickerFileNameDxp, "%s\\%08X.sticker", path, selectedCarCodeDxp);

		// If the specific car file exists
		if (FileExists(carFileNameDxp))
		{
			// Load the car file
			status = loadCarFile(carFileNameDxp);
		}
	}

	// Load the custom title file
	loadCustomTitle(titleFileNameDxp);

	// Load the custom name file
	loadCustomName(nameFileNameDxp);

	// Load the custom sticker file
	loadCustomSticker(stickerFileNameDxp);

	// If the force full tune switch is set
	if (ToBool(config["Tune"]["Force Full Tune"]))
	{
		// Set the car to be fully tuned
		setFullTune();
	}

#ifdef _DEBUG
	status ? writeLog("loadCarData failed.") : writeLog("loadCarData success.");
#endif

	// Return status code
	return status;
}

static int saveSettingsData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to saveSettingData...");
#endif

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", path, SETTINGS_FILENAME);

	// Save story data

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where the player story data starts
	uintptr_t settingsPtr = *(uintptr_t*)(savePtr + SETTINGS_OFFSET);

	// Dump the save data to openprogress.sav
	bool status = dumpMemory(path, settingsPtr, SETTINGS_DATA_SIZE);

#ifdef _DEBUG
	status ? writeLog("saveSettingData failed.") : writeLog("saveSettingData success.");
#endif

	// Return status code
	return status;
}

static int loadSettingsData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to loadSettingsData...");
#endif

	// Save data dump memory block
	unsigned char settingsData[SETTINGS_DATA_SIZE];

	// Zero out the save data array
	memset(settingsData, 0x0, SETTINGS_DATA_SIZE);

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0x0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", path, SETTINGS_FILENAME);

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Story save data offset
	uintptr_t settingsPtr = *(uintptr_t*)(savePtr + SETTINGS_OFFSET);

	// Open the openprogress file with read privileges	
	FILE* file = fopen(path, "rb");

	// Status code (default: failed to load file)
	int status = 1;

	// If the file exists
	if (file)
	{
		// Get all of the contents from the file
		fseek(file, 0, SEEK_END);

		// Get the size of the file
		int fsize = ftell(file);

		// Check file is correct size
		if (fsize == SETTINGS_DATA_SIZE)
		{
			// Reset seek index to start
			fseek(file, 0, SEEK_SET);

			// Read all of the contents of the file into storyDataDxp
			fread(settingsData, fsize, 1, file);

			// Copy the saved settings data from the settings file into the game
			// memcpy((void*)(settingsPtr + 0x08), (void*)(settingsData + 0x08), (SETTINGS_DATA_SIZE - 0x08)); 
			// memcpy((void*)(settingsPtr + 0x08), (void*)(settingsData + 0x08), 0x08); // First row (last 2 blocks) (Crash after title update)

			// Transmission setting is in 0x19 - Carefully importing 0x10 -> 0x1F to avoid it
			memcpy((void*)(settingsPtr + 0x14), (void*)(settingsData + 0x14), 0x05); // Second row (0x14 -> 0x18)
			memcpy((void*)(settingsPtr + 0x1A), (void*)(settingsData + 0x1A), 0x06); // Second row (0x1A -> 0x2F)
			
			memcpy((void*)(settingsPtr + 0x20), (void*)(settingsData + 0x20), 0x10); // Third row (entire row)
			memcpy((void*)(settingsPtr + 0x30), (void*)(settingsData + 0x30), 0x10); // Fourth row (entire row)

			// Success code
			status = 0;
		}
		else // Story file is incorrect size
		{
			// Incorrect size error code
			status = 2;
		}

		// Close the file
		fclose(file);
	}
	else // File does not exist
	{
		// Create the car settings file
		saveSettingsData(filepath);
	}

	// If a non-default custom meter is selected in the drop-down
	if (strcmp(config["General"]["Custom Meter"].c_str(), "Default") != 0)
	{
		// Not sure if I can clean this up, this is just how the MT6 code does the neons

		// Big if-else block for the different meter settings

		if (strcmp(config["General"]["Custom Meter"].c_str(), "White Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Yellow Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x2, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Red Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x3, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Special Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x4, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Blue Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x5, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Carbon Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x6, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Metallic Meter (Black)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x7, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Metallic Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x8, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Cyber Meter (Blue)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x9, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Cyber Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x20), 0xA, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Aluminium Meter (Blue)") == 0)
			memset((void*)(settingsPtr + 0x20), 0xB, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Aluminium Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x20), 0xC, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Camoflage Meter (Green)") == 0)
			memset((void*)(settingsPtr + 0x20), 0xD, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Camoflage Meter (Brown)") == 0)
			memset((void*)(settingsPtr + 0x20), 0xE, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Bronze Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x20), 0xF, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Bronze Meter (Brown)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x10, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Pirate Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x11, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Pirate Meter (Blue)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x12, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Fire Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x13, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Fire Meter (Blue)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x14, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Silver Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x15, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Gold Meter") == 0)
			memset((void*)(settingsPtr + 0x20), 0x16, 0x1);
		
		/* Undiscovered offsets
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Steampunk Meter (Gold)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x17, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Steampunk Meter (Green)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x18, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Dragon Meter (Gold)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x19, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Dragon Meter (Blue)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1A, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Light Line Meter (Blue)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1B, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Light Line Meter (Orange)") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1C, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Digital Black") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1D, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Digital Blue") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1E, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "High-End Red") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1F, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Digital Yellow") == 0)
			memset((void*)(settingsPtr + 0x20), 0x20, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "High-End Yellow") == 0)
			memset((void*)(settingsPtr + 0x20), 0x21, 0x1);
		*/
	}

	// If a non-default custom soundtrack is selected in the drop-down
	if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "Default") != 0)
	{
		// Not sure if I can clean this up, this is just how the MT6 code does the neons

		// Big if-else block for the different soundtrack settings

		if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "Maximum Tune 3/DX/DX+") == 0)
			memset((void*)(settingsPtr + 0x28), 0x1, 0x1);
		else if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "10 Outrun") == 0)
			memset((void*)(settingsPtr + 0x28), 0x2, 0x1);
		else if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "Maximum Tune 1/2") == 0)
			memset((void*)(settingsPtr + 0x28), 0x3, 0x1);
		else if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "Maximum Tune R") == 0)
			memset((void*)(settingsPtr + 0x28), 0x4, 0x1);
		else if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "Maximum Tune 4") == 0)
			memset((void*)(settingsPtr + 0x28), 0x5, 0x1);
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadSettingsData success.");
		break;
	case 1: // No file
		writeLog("loadSettingsData failed: No file. Default file will be created.");
		break;
	case 2: // File wrong size
		writeLog("loadSettingsData failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadSettingsData failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

static int saveCarData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to saveCarData...");
#endif

	memset(carFileNameDxp, 0, FILENAME_MAX);

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\OpenParrot_Cars");
	sprintf(path, "%s\\%s", path, CAR_FILEPATH);

	// Create the cars path folder
	std::filesystem::create_directories(path);

	// carFileNameDxp

	// If custom car is set
	if (customCarDxp)
	{
		// Save the file to custom.car
		sprintf(carFileNameDxp, "%s\\custom.car", path);
	}
	else // Custom car is not set
	{
		// Save the file to the specific car filename
		sprintf(carFileNameDxp, "%s\\%08X.car", path, selectedCarCodeDxp);
	}

	// Success status for the custom car file dump
	bool status = dumpMemory(carFileNameDxp, carSaveBase, CAR_DATA_SIZE);

#ifdef _DEBUG
	status ? writeLog("saveCarData failed.") : writeLog("saveCarData success.");
#endif

	// Return status code
	return status;
}

// loadStoryData(filepath: char *): Void
// Given a filepath, loads the story data 
// from the file into memory.
static int loadStoryData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to loadStoryData...");
#endif

	// Save data dump memory block
	unsigned char storyDataDxp[STORY_DATA_SIZE];

	// Zero out the save data array
	memset(storyDataDxp, 0x0, STORY_DATA_SIZE);

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0x0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", path, STORY_FILENAME);


	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Story save data offset
	uintptr_t saveStoryBase = *(uintptr_t*)(savePtr + STORY_OFFSET);

	// Open the openprogress file with read privileges	
	FILE* file = fopen(path, "rb");

	// Status code (default: failed to load file)
	int status = 1;

	// If the file exists
	if (file)
	{
		// Get all of the contents from the file
		fseek(file, 0, SEEK_END);

		// Get the size of the file
		int fsize = ftell(file);

		// Check file is correct size
		if (fsize == STORY_DATA_SIZE)
		{
			// Reset seek index to start
			fseek(file, 0, SEEK_SET);

			// Read all of the contents of the file into storyDataDxp
			fread(storyDataDxp, fsize, 1, file);

			// If the chapter 29 fix is enabled
			if (ToBool(config["General"]["Chapter29Fix"]))
			{
				// Check what chapter the player is up to

				// If you are up to chapter 2
				if (storyDataDxp[0xF0] % 3 == 1)
				{
					// Set the first bit in 0xE0 to 1
					storyDataDxp[0xED] |= 1;

					// Set the value in memory to the updated value
					// memset((void*)(saveStoryBase + 0xED), storyDataDxp[0xED], 0x1);

					// If we have done all of the other chapters
					if ((storyDataDxp[0xEC] & 0xE0) == 0xE0)
					{
						// Clear the locked final chapter
						storyDataDxp[0x111] &= ~(0x2);

						// Set the value in memory to the updated value
						// memset((void*)(saveStoryBase + 0x111), storyDataDxp[0x111], 0x1);
					}

					// Fix the story tune (to make up for the skipped chapter)
					fixStoryTune();
				}
			}

			// 0x00 - 08 4C - Should be able to use this to figure out what game a save is from

			// (Mostly) discovered story data

			memcpy((void*)(saveStoryBase + 0x48), storyDataDxp + 0x48, 0x8); // Story Bit
			memcpy((void*)(saveStoryBase + 0xE0), storyDataDxp + 0xE0, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0xE8), storyDataDxp + 0xE8, 0x8); // Chapter Progress (0xE8) (Bitmask)
			memcpy((void*)(saveStoryBase + 0xF0), storyDataDxp + 0xF0, 0x8); // Current Chapter (0xF0), Total Wins (0xF4)
			memcpy((void*)(saveStoryBase + 0xF8), storyDataDxp + 0xF8, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x100), storyDataDxp + 0x100, 0x8); // Win Streak (0x104)
			memcpy((void*)(saveStoryBase + 0x108), storyDataDxp + 0x108, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x110), storyDataDxp + 0x110, 0x8); // Locked Chapters (0x110) (Bitmask)
			
			// Can't tell if the data past this point does anything
			
			// memcpy((void*)(saveStoryBase + 0x118), storyDataDxp + 0x118, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x120), storyDataDxp + 0x120, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x128), storyDataDxp + 0x128, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x130), storyDataDxp + 0x130, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x138), storyDataDxp + 0x138, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x140), storyDataDxp + 0x140, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x148), storyDataDxp + 0x148, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x150), storyDataDxp + 0x150, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x158), storyDataDxp + 0x158, 0x8); // ??

			// Save data loaded successfully
			loadOkDxp = true;

			// Success code
			status = 0;
		}
		else // Story file is incorrect size
		{
			// Incorrect size error code
			status = 2;
		}

		// Close the file
		fclose(file);
	}
	else // No story file
	{
		// If the start with 60 stories option is set
		if (ToBool(config["Story"]["Start at 60 Stories"]))
		{
			// Set total wins to 60
			memset((void*)(saveStoryBase + 0xF4), 0x3C, 0x1);

			// Set win streak to 60
			memset((void*)(saveStoryBase + 0x100), 0x3C, 0x1);

			// Set the current chapter to 3 (3 Chapters cleared)
			memset((void*)(saveStoryBase + 0xF0), 0x3, 0x1);
		}
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadStoryData success.");
		break;
	case 1: // No file
		writeLog("loadStoryData failed: No file.");
		break;
	case 2: // File wrong size
		writeLog("loadStoryData failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadStoryData failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

static int saveStoryData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to saveStoryData...");
#endif

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", path, STORY_FILENAME);

	// Save story data

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where the player story data starts
	uintptr_t storySaveBase = *(uintptr_t*)(savePtr + STORY_OFFSET);

	// Dump the save data to openprogress.sav
	bool status = dumpMemory(path, storySaveBase, STORY_DATA_SIZE);

#ifdef _DEBUG
	status ? writeLog("saveStoryData failed.") : writeLog("saveStoryData success.");
#endif

	// Return status code
	return status;
}

static int loadMileData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to loadMileData...");
#endif

	// Mile data dump memory block
	unsigned char mileData[MILE_DATA_SIZE];
	
	// Zero out the mile data memory
	memset(mileData, 0x0, MILE_DATA_SIZE);

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0x0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", path, MILE_FILENAME);

	// Path to the miles file
	FILE* file = fopen(path, "rb");

	// Success code (default: no file found)
	int status = 1;

	// File loaded OK
	if (file)
	{
		// Get the size of the file
		fseek(file, 0, SEEK_END);
		int mileSize = ftell(file);

		// If the file size is correct
		if (mileSize == MILE_DATA_SIZE)
		{
			// Load the content from the file into mileData
			fseek(file, 0x0, SEEK_SET);
			fread(mileData, mileSize, 0x1, file);

			// Get the pointer to the memory location storing the miles
			uintptr_t mileMemory = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET) + MILE_OFFSET;

			// Copy the mile data from the file into the memory location
			memcpy((void*)mileMemory, mileData, 0x4);

			// Success code
			status = 0;
		}
		else // Miles data file is an incorrect size
		{
			// Incorrect size error code
			status = 2;
		}

		// Close the miles file
		fclose(file);
	}


#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadMileData success.");
		break;
	case 1: // No file
		writeLog("loadMileData failed: No file.");
		break;
	case 2: // File wrong size
		writeLog("loadMileData failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadMileData failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

static int saveMileData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to saveMileData...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Get the data storing the miles
	auto mileData = (uintptr_t*)(savePtr + MILE_OFFSET);

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Copy the file path to the miles path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", path, MILE_FILENAME);

	// Load the miles file
	FILE* file = fopen(path, "wb");

	// Error code (default: failed)
	bool status = 1;

	// File opened successfully
	if (file)
	{
		// Write the miles data from memory to the miles file
		fwrite(mileData, 0x1, sizeof(mileData), file);

		// Close the file
		fclose(file);

		// Success
		status = 0;
	}

#ifdef _DEBUG
	status ? writeLog("saveMileData failed.") : writeLog("saveMileData success.");
#endif

	// Return status code
	return status;
}

// Credits to chery vtec tuning club for figuring out star loading / saving
static int saveVersusData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to saveVersusData...");
#endif

	// Star path saving
	char path[FILENAME_MAX];

	// Set the versus  memory to zero
	memset(path, 0, FILENAME_MAX);

	// Copy the file path to the stars path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openversus.sav");
	sprintf(path, "%s\\%s", path, VERSUS_FILENAME);

	// Save Star Data

	// Dereference the versus pointer
	// Add 0x200 to it, because all of the versus stuff is after the first 0x200 bytes
	uintptr_t versusPtr = *(uintptr_t*)((*(uintptr_t*)(imageBaseDxp + SAVE_OFFSET)) + 0x110) + 0x200;

	// Dump the contents of the star data array to the file
	bool status = dumpMemory(path, versusPtr, VERSUS_DATA_SIZE);

#ifdef _DEBUG
status ? writeLog("saveVersusData failed.") : writeLog("saveVersusData success.");
#endif

	// Return status code
	return status;
}

static int loadVersusData(char* filepath)
{
#ifdef _DEBUG
	writeLog("Call to loadVersusData...");
#endif

	// Star data dump memory block
	unsigned char versusData[VERSUS_DATA_SIZE];

	// Clear star data memory
	memset(versusData, 0, VERSUS_DATA_SIZE);

	// Star path loading
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Copy the file path to the stars path
	strcpy(path, filepath);

	// Append the mileage filename to the string
	// strcat(path, "\\openversus.sav");
	sprintf(path, "%s\\%s", path, VERSUS_FILENAME);

	// Dereference the versus pointer in the game memory
	// Add 0x200 to it, because all of the versus stuff is after the first 0x200 bytes
	uintptr_t versusPtr = *(uintptr_t*)((*(uintptr_t*)(imageBaseDxp + SAVE_OFFSET)) + 0x110) + 0x200;

	// Open the star binary file
	FILE* file = fopen(path, "rb");

	// Status code (default: No file)
	int status = 1;

	// If the file opened successfully
	if (file)
	{
		// If the file size is correct
		fseek(file, 0, SEEK_END);
		int fileSize = ftell(file);
		if (fileSize == VERSUS_DATA_SIZE)
		{
			// Reset the file pointer to the start
			fseek(file, 0, SEEK_SET);

			// Read all of the contents into the array
			fread(versusData, fileSize, 1, file);

			// Load the data from the versus region

			memcpy((void*)(versusPtr + 0x10), versusData + 0x10, 0x8); // ???
			memcpy((void*)(versusPtr + 0x18), versusData + 0x18, 0x8); // ???
			memcpy((void*)(versusPtr + 0x20), versusData + 0x20, 0x8); // Player Count (0x24)
			memcpy((void*)(versusPtr + 0x28), versusData + 0x28, 0x8); // ???
			
			memcpy((void*)(versusPtr + 0x30), versusData + 0x30, 0x8); // ???
			memcpy((void*)(versusPtr + 0x38), versusData + 0x38, 0x8); // Unknown 0x1 (0x8)
			memcpy((void*)(versusPtr + 0x40), versusData + 0x40, 0x8); // Win Streak (??)
			memcpy((void*)(versusPtr + 0x48), versusData + 0x48, 0x8); // Stars (0x48), ??? (0x4C)
			
			memcpy((void*)(versusPtr + 0x50), versusData + 0x50, 0x8); // Gold Medals (0x54) ??
			memcpy((void*)(versusPtr + 0x58), versusData + 0x58, 0x8); // Silver Medals (0x58), Bronze Medals (0x5C) ??
			memcpy((void*)(versusPtr + 0x60), versusData + 0x60, 0x8); // Black Medals (0x60)
			memcpy((void*)(versusPtr + 0x68), versusData + 0x68, 0x8); // ??
			
			memcpy((void*)(versusPtr + 0x70), versusData + 0x70, 0x8); // ??
			memcpy((void*)(versusPtr + 0x78), versusData + 0x78, 0x8); // ??
			memcpy((void*)(versusPtr + 0x80), versusData + 0x80, 0x8); // ??

			// Success
			status = 0;
		}
		else // File size is incorrect
		{
			// Incorrect size status code
			status = 2;
		}

		// Close the miles file
		fclose(file);
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadVersusData success.");
		break;
	case 1: // No file
		writeLog("loadVersusData failed: No file.");
		break;
	case 2: // File wrong size
		writeLog("loadVersusData failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadVersusData failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

static int loadGameData()
{
#ifdef _DEBUG
	writeLog("Call to loadGameData...");
#endif

#ifdef _DEBUG
	// dumpPointerMemory();
#endif

	// Disable saving
	saveOk = false;

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Write the '.' into the load path
	sprintf(path, ".");

	// Get the path to the selected car
	selectedCarCodeDxp = *(DWORD*)(*(uintptr_t*)(*(uintptr_t*)(imageBaseDxp + SAVE_OFFSET) + CAR_OFFSET) + 0x34);

	// Seperate save file / cars per user profile
	if (ToBool(config["Save"]["Save Per Custom Name"]))
	{
		// Get the profile name from the 
		std::string name = config["General"]["CustomName"];

		// Add the c string version of the profile name to the path
		sprintf(path, "%s\\%s", path, name.c_str());
	}

	// Seperate miles / story per car
	if (ToBool(config["Save"]["Save Per Car"]))
	{
		// Need to get the hex code for the selected car

		// Add the custom folder to the save path
		sprintf(path, "%s\\%08X", path, selectedCarCodeDxp);
	}

	// Ensure the directory exists
	std::filesystem::create_directories(path);

	// Sleep for 1 second
	std::this_thread::sleep_for(std::chrono::seconds(1));

	// Load the car save file
	loadCarData(path);

	// Load the car settings file
	loadSettingsData(path);

	// Load the openprogress.sav file
	loadStoryData(path);

	// Load the miles save file
	loadMileData(path);

	// Sleep for 30 seconds (Thanks Chery!)
	std::this_thread::sleep_for(std::chrono::seconds(30));

	// Load the stars save file
	loadVersusData(path);

#ifdef _DEBUG
	writeLog("loadGameData done.");
#endif

	return 0;
}



// saveGameData(void): Int
// If saving is enabled, loads the 
// player story data 
static int saveGameData()
{
#ifdef _DEBUG
	writeLog("Call to saveGameData...");
#endif

	// Saving is disabled
	if (!saveOk)
		return 1;

	// Miles path string
	char path[FILENAME_MAX];

	// Set the path memory to zero
	memset(path, 0, FILENAME_MAX);

	// Write the '.' into the load path
	sprintf(path, ".");

	// Seperate save file / cars per user profile
	if (ToBool(config["Save"]["Save Per Custom Name"]))
	{
		// Get the profile name from the 
		std::string name = config["General"]["CustomName"];

		// Add the c string version of the profile name to the path
		sprintf(path, "%s\\%s", path, name.c_str());
	}

	// Seperate miles / story per car
	if (ToBool(config["Save"]["Save Per Car"]))
	{
		// Need to get the hex code for the selected car

		// If custom car is set
		if (customCarDxp)
		{
			// Add the car id to the save path
			sprintf(path, "%s\\custom", path);
		}
		else // Custom car is not set
		{
			// Add the custom folder to the save path
			sprintf(path, "%s\\%08X", path, selectedCarCodeDxp);
		}
	}

	// Ensure the directory exists
	std::filesystem::create_directories(path);

	// Load the car save file
	saveCarData(path);

	// Load the openprogress.sav file
	saveStoryData(path);

	// Load the miles save file
	saveMileData(path);

	// Load the miles save file
	saveVersusData(path);

	// Disable saving
	saveOk = false;

#ifdef _DEBUG
	writeLog("saveGameData done.");
#endif

	// Success
	return 0;
}

static void loadGame()
{
#ifdef _DEBUG
	writeLog("Call to loadGame ...");
#endif

	// Runs after car data is loaded

	// Load story data thread
	std::thread t1(loadGameData);
	t1.detach();

#ifdef _DEBUG
	writeLog("loadGame done.");
#endif
}

static int returnTrue()
{
	return 1;
}

void generateDongleData(bool isTerminal)
{
#ifdef _DEBUG
	writeLog("Call to generateDongleData ...");
#endif

	memset(hasp_buffer, 0, 0xD40);
	hasp_buffer[0] = 0x01;
	hasp_buffer[0x13] = 0x01;
	hasp_buffer[0x17] = 0x0A;
	hasp_buffer[0x1B] = 0x04;
	hasp_buffer[0x1C] = 0x3B;
	hasp_buffer[0x1D] = 0x6B;
	hasp_buffer[0x1E] = 0x40;
	hasp_buffer[0x1F] = 0x87;

	hasp_buffer[0x23] = 0x01;
	hasp_buffer[0x27] = 0x0A;
	hasp_buffer[0x2B] = 0x04;
	hasp_buffer[0x2C] = 0x3B;
	hasp_buffer[0x2D] = 0x6B;
	hasp_buffer[0x2E] = 0x40;
	hasp_buffer[0x2F] = 0x87;

	if(isTerminal)
	{
		memcpy(hasp_buffer + 0xD00, "278311042069", 12); //272211990002
		hasp_buffer[0xD3E] = 0x6B;
		hasp_buffer[0xD3F] = 0x94;
	}
	else
	{
		memcpy(hasp_buffer + 0xD00, "278313042069", 12); //272213990002
		hasp_buffer[0xD3E] = 0x6D;
		hasp_buffer[0xD3F] = 0x92;
	}

#ifdef _DEBUG
	writeLog("generateDongleData done.");
#endif
}

static DWORD WINAPI spamMulticast(LPVOID)
{
#ifdef _DEBUG
	writeLog("Call to spamMulticast ...");
#endif

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	int ttl = 255;
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl));

	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&reuse, sizeof(reuse));

	sockaddr_in bindAddr = { 0 };
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_addr.s_addr = inet_addr(ipaddrdxplus);
	bindAddr.sin_port = htons(50765);
	bind(sock, (sockaddr*)&bindAddr, sizeof(bindAddr));
	

	ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr("225.0.0.1");
	mreq.imr_interface.s_addr = inet_addr(ipaddrdxplus);

	setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));

	const uint8_t* byteSequences_Free[] = {
		dxpterminalPackage1_Free,
		dxpterminalPackage2_Free,
		dxpterminalPackage3_Free,
		dxpterminalPackage4_Free,
		dxpterminalPackage5_Free,
		dxpterminalPackage6_Free,
	};

	const size_t byteSizes_Free[] = {
		sizeof(dxpterminalPackage1_Free),
		sizeof(dxpterminalPackage2_Free),
		sizeof(dxpterminalPackage3_Free),
		sizeof(dxpterminalPackage4_Free),
		sizeof(dxpterminalPackage5_Free),
		sizeof(dxpterminalPackage6_Free),
	};
	
	const uint8_t* byteSequences_Event2P[] = {
		dxpterminalPackage1_Event2P,
		dxpterminalPackage2_Event2P,
		dxpterminalPackage3_Event2P,
		dxpterminalPackage4_Event2P,
		dxpterminalPackage5_Event2P,
		dxpterminalPackage6_Event2P,
	};

	const size_t byteSizes_Event2P[] = {
		sizeof(dxpterminalPackage1_Event2P),
		sizeof(dxpterminalPackage2_Event2P),
		sizeof(dxpterminalPackage3_Event2P),
		sizeof(dxpterminalPackage4_Event2P),
		sizeof(dxpterminalPackage5_Event2P),
		sizeof(dxpterminalPackage6_Event2P),
	};

	const uint8_t* byteSequences_Event4P[] = {
		dxpterminalPackage1_Event4P,
		dxpterminalPackage2_Event4P,
		dxpterminalPackage3_Event4P,
		dxpterminalPackage4_Event4P,
		dxpterminalPackage5_Event4P,
		dxpterminalPackage6_Event4P,
	};

	const size_t byteSizes_Event4P[] = {
		sizeof(dxpterminalPackage1_Event4P),
		sizeof(dxpterminalPackage2_Event4P),
		sizeof(dxpterminalPackage3_Event4P),
		sizeof(dxpterminalPackage4_Event4P),
		sizeof(dxpterminalPackage5_Event4P),
		sizeof(dxpterminalPackage6_Event4P),
	};

	const uint8_t* byteSequences_Coin[] = {
		dxpterminalPackage1_Coin,
		dxpterminalPackage2_Coin,
		dxpterminalPackage3_Coin,
		dxpterminalPackage4_Coin,
		dxpterminalPackage5_Coin,
		dxpterminalPackage6_Coin,
	};

	const size_t byteSizes_Coin[] = {
		sizeof(dxpterminalPackage1_Coin),
		sizeof(dxpterminalPackage2_Coin),
		sizeof(dxpterminalPackage3_Coin),
		sizeof(dxpterminalPackage4_Coin),
		sizeof(dxpterminalPackage5_Coin),
		sizeof(dxpterminalPackage6_Coin),
	};
	
	sockaddr_in toAddr = { 0 };
	toAddr.sin_family = AF_INET;
	toAddr.sin_addr.s_addr = inet_addr("225.0.0.1");
	toAddr.sin_port = htons(50765);
	
	
	isFreePlay = ToBool(config["General"]["FreePlay"]);
	isEventMode2P = ToBool(config["TerminalEmuConfig"]["2P Event Mode"]);
	isEventMode4P = ToBool(config["TerminalEmuConfig"]["4P Event Mode"]);
	
	
	if (isFreePlay)
	{
		if (isEventMode2P) {
			while (true) for (int i = 0; i < _countof(byteSequences_Event2P); i++)
			{
				sendto(sock, (const char*)byteSequences_Event2P[i], byteSizes_Event2P[i], 0, (sockaddr*)&toAddr, sizeof(toAddr));
				Sleep(8);
			}
		}
		else if (isEventMode4P) {
			while (true) for (int i = 0; i < _countof(byteSequences_Event4P); i++)
			{
				sendto(sock, (const char*)byteSequences_Event4P[i], byteSizes_Event4P[i], 0, (sockaddr*)&toAddr, sizeof(toAddr));
				Sleep(8);
			}
		}
		else {
			while (true) for (int i = 0; i < _countof(byteSequences_Free); i++)
			{
				sendto(sock, (const char*)byteSequences_Free[i], byteSizes_Free[i], 0, (sockaddr*)&toAddr, sizeof(toAddr));
				Sleep(8);
			}
		}
	}
	
	while (true) for (int i = 0; i < _countof(byteSequences_Coin); i++)
	{
		sendto(sock, (const char*)byteSequences_Coin[i], byteSizes_Coin[i], 0, (sockaddr*)&toAddr, sizeof(toAddr));
		Sleep(8);
	}

#ifdef _DEBUG
	writeLog("spamMulticast done.");
#endif
}

// Wmmt5Func([]()): InitFunction
// Performs the initial startup tasks for 
// maximum tune 5, including the starting 
// of required subprocesses.
static InitFunction Wmmt5Func([]()
{
#ifdef _DEBUG
	writeLog("Game: Wangan Midnight Maximum Tune 5DX+");
	writeLog("Call to init function ...");
#endif

	// Records if terminal mode is enabled
	bool isTerminal = false;

	// If terminal mode is set in the general settings
	if (ToBool(config["General"]["TerminalMode"]))
	{
		// Terminal mode is set
		isTerminal = true;
	}
	
	// Get the network adapter ip address from the general settings
	std::string networkip = config["General"]["NetworkAdapterIP"];

	// If the ip address is not blank
	if (!networkip.empty())
	{
		// Overwrite the default ip address
		ipaddrdxplus = networkip.c_str();
	}

	hookPort = "COM3";
	imageBaseDxp = (uintptr_t)GetModuleHandleA(0);

	MH_Initialize();

	// Hook dongle funcs
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_write", hook_hasp_write, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_read", hook_hasp_read, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_get_size", hook_hasp_get_size, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_decrypt", hook_hasp_decrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_encrypt", hook_hasp_encrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_logout", hook_hasp_logout, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_login", hook_hasp_login, NULL);

	generateDongleData(isTerminal);

	// Prevents game from setting time, thanks pockywitch!
	MH_CreateHookApi(L"KERNEL32", "SetSystemTime", Hook_SetSystemTime, reinterpret_cast<LPVOID*>(&pSetSystemTime));

	// Patch some check TEMP DISABLE AS WELL OVER HERE
	// 0F 94 C0 84 C0 0F 94 C0 84 C0 75 05 45 32 E4 EB 03 41 B4 01
	// FOUND ON 21, 10
	// NOT WORKING 1
	// 0F 94 C0 84 C0 0F 94 C0 84 C0 75 05 45 32 ?? EB
	// FOUND ON 1
	//injector::WriteMemory<uint8_t>(imageBase + 0x6286EC, 0, true); 
	injector::WriteMemory<uint8_t>(hook::get_pattern("85 C9 0F 94 C0 84 C0 0F 94 C0 84 C0 75 ? 40 32 F6 EB ?", 0x15), 0, true); //patches out dongle error2 (doomer)

	// Patch some jnz
	// 83 C0 FD 83 F8 01 0F 87 B4 00 00 00 83 BF D0 06 00 00 3C 73 29 48 8D 8D 60 06 00 00
	// FOUND ON 21, 10
	// NOT FOUND: 1
	// 83 C0 FD 83 F8 01 0F 87 B4 00 00 00
	// FOUND ON 1
	//injector::MakeNOP(imageBase + 0x628AE0, 6);
	//THIS injector::MakeNOP(hook::get_pattern("83 C0 FD 83 F8 01 0F 87 B4 00 00 00", 6), 6);
	injector::MakeNOP(hook::get_pattern("83 C0 FD 83 F8 01 76 ? 49 8D ? ? ? ? 00 00"), 6);

	// Patch some shit
	// 83 FA 04 0F 8C 1E 01 00 00 4C 89 44 24 18 4C 89 4C 24 20
	// FOUND ON 21, 10, 1
	// NOT FOUND:
	//injector::WriteMemory<uint8_t>(imageBase + 0x7B9882, 0, true);
	//THIS injector::WriteMemory<uint8_t>(hook::get_pattern("83 FA 04 0F 8C 1E 01 00 00 4C 89 44 24 18 4C 89 4C 24 20", 2), 0, true);
		
	// Skip weird camera init that stucks entire pc on certain brands. TESTED ONLY ON 05!!!!
	if (ToBool(config["General"]["WhiteScreenFix"]))
	{
		injector::WriteMemory<DWORD>(hook::get_pattern("48 8B C4 55 57 41 54 41 55 41 56 48 8D 68 A1 48 81 EC 90 00 00 00 48 C7 45 D7 FE FF FF FF 48 89 58 08 48 89 70 18 45 33 F6 4C 89 75 DF 33 C0 48 89 45 E7", 0), 0x90C3C032, true);
	}

	// Patch some call
	// 45 33 C0 BA 65 09 00 00 48 8D 4D B0 E8 ?? ?? ?? ?? 48 8B 08
	// FOUND ON 21, 10, 1

	{
		// 199AE18 TIME OFFSET RVA temp disable ALL JNZ PATCH

		auto location = hook::get_pattern<char>("41 3B C7 74 0E 48 8D 8F B8 00 00 00 BA F6 01 00 00 EB 6E 48 8D 8F A0 00 00 00");
		
		// Patch some jnz
		// 41 3B C7 74 0E 48 8D 8F B8 00 00 00 BA F6 01 00 00 EB 6E 48 8D 8F A0 00 00 00
		// FOUND ON 21, 10, 1
		injector::WriteMemory<uint8_t>(location + 3, 0xEB, true); //patches content router (doomer)

		// Skip some jnz
		injector::MakeNOP(location + 0x22, 2); //patches ip addr error again (doomer)

		// Skip some jnz
		injector::MakeNOP(location + 0x33, 2); //patches ip aaddr error(doomer)
	}

	// Terminal mode is off
	if (!isTerminal)
	{
		// Disregard terminal scanner stuff.
		// 48 8B 18 48 3B D8 0F 84 88 00 00 00 39 7B 1C 74 60 80 7B 31 00 75 4F 48 8B 43 10 80 78 31 00
		// FOUND ON 21, 10, 1
		//injector::MakeNOP(imageBase + 0x91E1AE, 6);
		//injector::MakeNOP(imageBase + 0x91E1B7, 2);
		//injector::MakeNOP(imageBase + 0x91E1BD, 2);

		/*
		auto location = hook::get_pattern<char>("48 8B 18 48 3B D8 0F 84 8B 00 00 00 0F 1F 80 00 00 00 00 39 73 1C 74 5C 80 7B 31 00");
		// injector::MakeNOP(location + 6, 6); // 6
		injector::MakeNOP(location + 0xF, 2); // 0xF
		// injector::MakeNOP(location + 0x15, 2); // 0x15
		*/

		injector::MakeNOP(imageBaseDxp + 0x9F2BB3, 2);

		// If terminal emulator is enabled
		if (ToBool(config["General"]["TerminalEmulator"]))
		{
			// Start the multicast spam thread
			CreateThread(0, 0, spamMulticast, 0, 0, 0);
		}
	}
	/*
	else
	{
		// Patch some func to 1
		// 
		// FOUND ON 21, 10, 1
		// NOT FOUND:
		//safeJMP(imageBase + 0x7BE440, returnTrue);
		//safeJMP(hook::get_pattern("0F B6 41 05 2C 30 3C 09 77 04 0F BE C0 C3 83 C8 FF C3"), returnTrue);
		//safeJMP(imageBase + 0x89D420, returnTrue);

		// Patch some func to 1
		// 40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 28 48 8D ?? ?? ?? ?? 00 48 8D ?? ?? ?? ?? 00 41 B8 ?? ?? 00 00 FF 15 ?? ?? ?? ?? 4C 8B 1B 41 0F B6 43 78
		// FOUND ON 21, 10, 1
		//safeJMP(imageBase + 0x7CF8D0, returnTrue); 
		//safeJMP(hook::get_pattern("40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 11 48 8B 0D C2"), returnTrue);
		//safeJMP(imageBase + 0x8B5190, returnTrue); 
	}
	*/

	auto chars = { 'F', 'G' };

	for (auto cha : chars)
	{
		auto patterns = hook::pattern(va("%02X 3A 2F", cha));

		if (patterns.size() > 0)
		{
			for (int i = 0; i < patterns.size(); i++)
			{
				char* text = patterns.get(i).get<char>(0);
				std::string text_str(text);

				std::string to_replace = va("%c:/", cha);
				std::string replace_with = va("./%c", cha);

				std::string replaced = text_str.replace(0, to_replace.length(), replace_with);

				injector::WriteMemoryRaw(text, (char*)replaced.c_str(), replaced.length() + 1, true);
			}
		}
	}

	// Get the custom name specified in the  config file
	std::string customName = config["General"]["CustomName"];

	// If a custom name is set
	if (!customName.empty())
	{
		// Zero out the custom name variable
		memset(customNameDxp, 0, 256);

		// Copy the custom name to the custom name block
		strcpy(customNameDxp, customName.c_str());

		// Create the spam custom name thread
		// CreateThread(0, 0, spamCustomName, 0, 0, 0);
	}

	// Save story stuff (only 05)
	{
		// Enable all print
		injector::MakeNOP(imageBaseDxp + 0x898BD3, 6);

		// Load car and story data at once
		safeJMP(imageBaseDxp + 0x72AB90, loadGame);

		// Save car trigger
		// injector::WriteMemory<uintptr_t>(imageBase + 0x376F80 + 2, (uintptr_t)saveGameData, true);
		// safeJMP(imageBase + 0x376F76, saveGameData);

		// Save car trigger
		injector::MakeNOP(imageBaseDxp + 0x376F76, 0x12);
		injector::WriteMemory<WORD>(imageBaseDxp + 0x376F76, 0xB848, true);
		injector::WriteMemory<uintptr_t>(imageBaseDxp + 0x376F76 + 2, (uintptr_t)saveGameData, true);
		injector::WriteMemory<DWORD>(imageBaseDxp + 0x376F80, 0x3348D0FF, true);
		injector::WriteMemory<WORD>(imageBaseDxp + 0x376F80 + 4, 0x90C0, true);

		// Prevents startup saving
		injector::WriteMemory<WORD>(imageBaseDxp + 0x6B909A, 0xB848, true);
		injector::WriteMemory<uintptr_t>(imageBaseDxp + 0x6B909A + 2, (uintptr_t)SaveOk, true);
		injector::WriteMemory<DWORD>(imageBaseDxp + 0x6B90A4, 0x9090D0FF, true);
	}

	MH_EnableHook(MH_ALL_HOOKS);

#ifdef _DEBUG
	writeLog("Init function done.");
#endif

}, GameID::WMMT5DXPlus);
#endif
#pragma optimize("", on)