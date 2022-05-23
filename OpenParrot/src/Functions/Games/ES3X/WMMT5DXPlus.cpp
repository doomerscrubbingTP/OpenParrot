#include <StdInc.h>
#include "Utility/InitFunction.h"
#include "Functions/Global.h"
#include <filesystem>
#include <iostream>
#include <cstdint>
#include <fstream>
#include "MinHook.h"
#include <Utility/Hooking.Patterns.h>
#include <chrono>
#include <thread>
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


#define HASP_STATUS_OK 0
unsigned int dxpHook_hasp_login(int feature_id, void* vendor_code, int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_login\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_logout(int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_logout\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_encrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_encrypt\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_decrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_decrypt\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_get_size(int hasp_handle, int hasp_fileid, unsigned int* hasp_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_get_size\n");
#endif
	*hasp_size = 0xD40; // Max addressable size by the game... absmax is 4k
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_read(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_read\n");
#endif
	memcpy(buffer, hasp_buffer + offset, length);
	return HASP_STATUS_OK;
}

unsigned int dxpHook_hasp_write(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
	return HASP_STATUS_OK;
}

//set system date patch by pockywitch
typedef bool (WINAPI* SETSYSTEMTIME)(SYSTEMTIME* in);
SETSYSTEMTIME pSetSystemTime = NULL;

bool WINAPI Hook_SetSystemTime(SYSTEMTIME* in)
{
	return TRUE;
}

// Maximum title length (16 Characters)
#define TITLE_LENGTH 0x10

// Maximum name length (16 bytes, 5 characters)
#define NAME_LENGTH 0x10

// Title string storage
char title[TITLE_LENGTH];

// Car Name string storage
char name[NAME_LENGTH];

// Save data dump memory block
unsigned char saveDatadxp[0x2000];

// Star data dump memory block
unsigned char versusDataDxp[0x100];

// Mile data dump memory block
unsigned char mileDatadxp[0x08];

// Car code of the selected car (in the menu)
unsigned char selectedCarCodeDxp;

// Sets if saving is allowed or not
static bool saveOk = false;

// If custom car is used
bool customCarDxp = false;

// Sets if loading is allowed
bool loadOkDxp = false;

// Car save data reserved memory
unsigned char carDataDxp[0xFF];

// Car filename string
char carFileNameDxp[0xFF];

// Title filename string
char titleFileNameDxp[0xFF];

// Car name filename string
char nameFileNameDxp[0xFF];

// SaveOk(void): Void
// Enables saving
static int SaveOk()
{
	saveOk = true;
	return 1;
}

// Save Data Location Constant
static uintptr_t saveLocation = 0x1F7D578;

// setFullTune(void): Int
// If the currently loaded car is NOT fully tuned, 
// updates the power and handling values to be fully
// tuned (16 for each). If they are already fully tuned,
// does not change any values.
static int setFullTune()
{
	// Get the memory addresses for the car base save, power and handling values
	auto carSaveBase = (uintptr_t*)(*(uintptr_t*)(imageBaseDxp + 0x01F7D578) + 0x268);
	auto powerAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase)+0xAC);
	auto handleAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase)+0xB8);

	// Dereference the power value from the memory address
	auto powerValue = injector::ReadMemory<uint8_t>(powerAddress, true);
	auto handleValue = injector::ReadMemory<uint8_t>(handleAddress, true);

	// If the power and handling values do not add up to fully tuned
	if (powerValue + handleValue < 0x20)
	{
		// Car is not fully tuned, force it to the default full tune
		injector::WriteMemory<uint8_t>(powerAddress, 0x10, true);
		injector::WriteMemory<uint8_t>(handleAddress, 0x10, true);

		// Updated
		return 1;
	}

	// Not updated
	return 0;
}

// forceFullTune(pArguments: void*): DWORD WINAPI
// Function which runs in a secondary thread if the forceFullTune
// option is selected in the menu. If the player's car is not fully
// tuned, it is forcibly set to max tune. If the player's car is already
// fully tuned, it is left alone. 
static DWORD WINAPI spamFullTune(void* pArguments)
{
	// Loops while the program is running
	while (true) {

		// Only runs every 16th frame
		Sleep(16);

		// Run the set full tune process
		setFullTune();
	}
}

/*
* 
* Warning - Crashes when title is overwritten!
* 
// Custom title (i.e. Wangan Beginner) (Max 32 characters)
char customTitleDxp[32];

static DWORD WINAPI spamCustomTitleDxp(LPVOID)
{
	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Address where the car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(saveDataBase + 0x268);

	// Infinite loop
	while (true)
	{
		// Wait 50ms
		Sleep(50);

		// Addres where the car title data starts
		uintptr_t titleSaveBase = *(uintptr_t*)(carSaveBase + 0xB0);

		// Write the custom title to the title pointer
		memcpy((void*)titleSaveBase, customTitleDxp, strlen(customTitleDxp) + 1);
	}
}
*/


// Custom name (i.e. Scrubbs)
char customNameDxp[256];

static DWORD WINAPI spamCustomNameDxp(LPVOID)
{
	// Infinite loop
	while (true)
	{
		// Wait 50ms
		Sleep(50);

		void* value = (void*)(imageBaseDxp + 0x1F846F0);
		memcpy(value, customNameDxp, strlen(customNameDxp) + 1);

	}
}

// ******************************************** //
// ************ Development  Tools ************ //
// ******************************************** //

// ************* Global Variables ************* //

// **** String Variables

// Debugging event log file
static std::string logfile = "wmmt5dxp_errors.txt";

// writeLog(filename: String, message: String): Int
// Given a filename string and a message string, appends
// the message to the given file.
static int writeLog(std::string filename, std::string message)
{
	// Log file to write to
	std::ofstream eventLog;

	// Open the filename provided (append mode)
	eventLog.open(filename, std::ios_base::app);

	// File open success
	if (eventLog.is_open()) 
	{
		// Write the message to the file
		eventLog << message;

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

// writeDump(filename: Char*, data: unsigned char *, size: size_t): Int
// Given a filename, a data buffer pointer and a size dumps 'size' data
// from 'data' to the filename provided by 'filename'. This code is used
// for most of the saving routines, and is not just  for dev purposes.
static int writeDump(char * filename, unsigned char * data, size_t size)
{
	// Open the file with the provided filename
	FILE* file = fopen(filename, "wb");

	// File opened successfully
	if (file)
	{
		// Write the data to the file
		fwrite((void*)data, 1, size, file);

		// Close the file
		fclose(file);

		// Return success status
		return 0;
	}
	else // Failed to open
	{
		// Return failure status
		return 1;
	}
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

// dumpMemory(filename: char*, memory: uintptr_t, size: size_t): Void
// Given a filename, a pointer to a position in memory and a size, dumps
// 'size' amount of data from 'memory' and writes it to the file 'filename'.
static int dumpMemory(char* filename, uintptr_t memory, size_t size)
{
	// Create the array to dump the memory data to
	unsigned char* data = (unsigned char*)malloc(size);

	// If malloc is successful
	if (data)
	{
		// Set all of the pointer data to zero
		memset(data, 0, size);

		// Copy the memory from the source
		memcpy(data, (void*)memory, size);

		// Write the memory to a file
		writeDump(filename, data, size);

		// Free the allocated memory
		free(data);

		// Success
		return 1;
	}

	// Failure
	return 0;
}

// Number of seconds to wait between writes
static int dumpMemoryDelay;
static std::string dumpMemoryFolder;
static uintptr_t dumpMemoryAddr;
static size_t dumpMemorySize;

// dumpMemoryThread(pArguments: void*): DWORD WINAPI
static DWORD WINAPI watchMemoryThread(void* pArguments)
{
	// File to dump the current memory to
	static char path[255];

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
}

// watchMemory(char * filename, uintptr_t memory, size_t size, int delay)
// Given a filename (folder path), memory pointer, size and delay continiously
// dumps 'size' data from memory address 'memory' incrementally to files in 
// the folder 'filename'. Memory will be dumped incrementally every 'delay' seconds.
// Unfortunately due to the reliance on global variables, only one dumpMemoryThread
// can be running at any time.
static void watchMemory(char* filename, uintptr_t memory, size_t size, int delay)
{
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
}

static int loadCustomSticker(char* filename)
{
	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(saveDataBase + 0x268);

	// DEBUG: Address where the window sticker (might be) saved
	uintptr_t stickerPtr = *(uintptr_t*)(carSaveBase + 0xC8);

	dumpMemory("stickerptr_pre.bin", stickerPtr, 0x20);

	// G
	memset((void*)(stickerPtr + 0x0), 0xEF, 0x1);
	memset((void*)(stickerPtr + 0x1), 0xBC, 0x1);
	memset((void*)(stickerPtr + 0x2), 0xA7, 0x1);

	// U
	memset((void*)(stickerPtr + 0x3), 0xEF, 0x1);
	memset((void*)(stickerPtr + 0x4), 0xBC, 0x1);
	memset((void*)(stickerPtr + 0x5), 0xB5, 0x1);

	// E
	memset((void*)(stickerPtr + 0x6), 0xEF, 0x1);
	memset((void*)(stickerPtr + 0x7), 0xBC, 0x1);
	memset((void*)(stickerPtr + 0x8), 0xA5, 0x1);

	// S
	memset((void*)(stickerPtr + 0x9), 0xEF, 0x1);
	memset((void*)(stickerPtr + 0xA), 0xBC, 0x1);
	memset((void*)(stickerPtr + 0xB), 0xB3, 0x1);

	// T
	memset((void*)(stickerPtr + 0xC), 0xEF, 0x1);
	memset((void*)(stickerPtr + 0xD), 0xBC, 0x1);
	memset((void*)(stickerPtr + 0xE), 0xB4, 0x1);

	dumpMemory("stickerptr_post.bin", stickerPtr, 0x20);

	return 1; // Success
}

/*
// Given a character, returns an integer
// which represents the full-width ascii
// for that character. If the character
// does not have a valid full width 
// equivalent, returns zero.
unsigned int getFullWidthChar(char c)
{
	// Table of full-width ascii values
	// Index is the ascii value of the character
	// minus 0x21 (the first valid full-width ascii character)
	unsigned int table[] = {

		0xEFBC81, // !
		0xEFBC82, // "
		0xEFBC83, // #
		0xEFBC84, // $
		0xEFBC85, // %
		0xEFBC86, // &
		0xEFBC87, // '
		0xEFBC88, // (
		0xEFBC89, // )
		0xEFBC8A, // *
		0xEFBC8B, // +
		0xEFBC8C, // ,
		0xEFBC8D, // -
		0xEFBC8E, // .
		0xEFBC8F, // /
		0xEFBC90, // 0
		0xEFBC91, // 1
		0xEFBC92, // 2
		0xEFBC93, // 3
		0xEFBC94, // 4
		0xEFBC95, // 5
		0xEFBC96, // 6
		0xEFBC97, // 7
		0xEFBC98, // 8
		0xEFBC99, // 9
		0xEFBC9A, // :
		0xEFBC9B, // ;
		0xEFBC9C, // <
		0xEFBC9D, // =
		0xEFBC9E, // >
		0xEFBC9F, // ?
		0xEFBCA0, // @
		0xEFBCA1, // A
		0xEFBCA2, // B
		0xEFBCA3, // C
		0xEFBCA4, // D
		0xEFBCA5, // E
		0xEFBCA6, // F
		0xEFBCA7, // G
		0xEFBCA8, // H
		0xEFBCA9, // I
		0xEFBCAA, // K
		0xEFBCAB, // L
		0xEFBCAC, // M
		0xEFBCAD, // N
		0xEFBCAE, // O
		0xEFBCAF, // P
		0xEFBCB0, // Q
		0xEFBCB1, // R
		0xEFBCB2, // S
		0xEFBCB3, // T
		0xEFBCB4, // U
		0xEFBCB5, // V
		0xEFBCB6, // W
		0xEFBCB7, // X
		0xEFBCB8, // Y
		0xEFBCB9, // Z
		0xEFBCBA, // [
		0xEFBCBB, // '\'
		0xEFBCBC, // ]
		0xEFBCBD, // ^
		0xEFBCBE, // _
		0xEFBD80, // `
		0xEFBD81, // a
		0xEFBD82, // b
		0xEFBD83, // c
		0xEFBD84, // d
		0xEFBD85, // e
		0xEFBD86, // f
		0xEFBD87, // g
		0xEFBD88, // h
		0xEFBD89, // i
		0xEFBD8A, // j
		0xEFBD8B, // k
		0xEFBD8C, // l
		0xEFBD8D, // m
		0xEFBD8E, // n
		0xEFBD8F, // o
		0xEFBD90, // p
		0xEFBD91, // q
		0xEFBD92, // r
		0xEFBD93, // s
		0xEFBD94, // t
		0xEFBD95, // u
		0xEFBD96, // v
		0xEFBD97, // w
		0xEFBD98, // x
		0xEFBD99, // y
		0xEFBD9A, // z
		0xEFBD9B, // {
		0xEFBD9C, // |
		0xEFBD9D, // }
		0xEFBD9E, // ~

	};

	// If c is at least 21, but not out of bounds
	if (c > 0x20 && c < sizeof(table)/sizeof(*table))
	{
		// Return the index for the character in the table
		return table[(c-0x20)];
	}
	else // Character is not in the table
	{
		// Return zero
		return 0;
	}
}
*/

// saveCustomName(filename: char*): Int
// Given a filename, saves the default custom name
// attribute to the file. Returns true on a successful execution.
static int saveCustomName(char* filename)
{
	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(saveDataBase + 0x268);

	// DEBUG: Address where the player name (might be) saved
	uintptr_t namePtr = *(uintptr_t*)(carSaveBase + 0x20);

	// Dump the default name to the file
	dumpMemory(filename, namePtr, NAME_LENGTH);

	return 1; // Success
}


// loadCustomName(filename: char*): Int
// Given a filename, loads the default custom name
// attribute from the file. If the file does not
// exist, it is created using saveCustomName. 
// Returns true on a successful execution.
static int loadCustomName(char* filename)
{
	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(saveDataBase + 0x268);

	// DEBUG: Address where the player name (might be) saved
	uintptr_t namePtr = *(uintptr_t*)(carSaveBase + 0x20);

	// Custom title file does not exist
	if (!(FileExists(filename)))
	{
		// Create the default file
		saveCustomName(filename);
	}

	// Open the file with the file name
	FILE* file = fopen(filename, "rb");

	// File is opened successfully
	if (file)
	{
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
		return 1;
	}

	return 1; // Success
}

// saveCustomTitle(filepath: char*): Int
// Saves the custom title value to the current car's title, 
// otherwise creates a default title.
static int saveCustomTitle(char* filename)
{
	// Get the custom title from the config
	std::string customTitle = config["General"]["CustomTitle"];

	// If the custom title is blank
	if (!customTitle.empty())
	{
		// Set to the default (Wangan Beginner)
		customTitle = "Wangan Beginner";
	}

	// Open the file for the title
	FILE* file = fopen(filename, "w+");

	// File is opened successfully
	if (file)
	{
		// Write the title string to the file
		fprintf(file, "%s", customTitle.c_str());

		// Close the file handle
		fclose(file);
	}
	else // Failed to open file
	{
		// Failure
		return 1;
	}
}

// loadCustomTitle(filepath: char*): Int
// Loads the title string from the title file for the given car.
static int loadCustomTitle(char* filename)
{
	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(saveDataBase + 0x268);

	// Address where the title is saved
	uintptr_t titlePtr = *(uintptr_t*)(carSaveBase + 0xB0);

	// Custom title file does not exist
	if (!(FileExists(filename)))
	{
		// Save the custom title
		saveCustomTitle(filename);
	}

	// Open the file with the file name
	FILE* file = fopen(filename, "rb");

	// File is opened successfully
	if (file)
	{
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
		return 1;
	}

	// Failure
	return 0;
}

/*
// saveTitle(filepath: char*): Int
// Saves the title string from memory for the given car.
static int saveTitleFile(char* filename)
{
	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(saveDataBase + 0x268);

	// Address where the title is saved
	uintptr_t titlePtr = *(uintptr_t*)(carSaveBase + 0xB0);

	// Array for storing title content
	unsigned char titleMem[TITLE_LENGTH];

	// Copy 'title length' number of characters from the title pointer
	memcpy(titleMem, (void*)titlePtr, TITLE_LENGTH);

	dumpMemory("title_presave.bin", titlePtr, 0x80);

	// Dump the title memory contents to the file
	writeDump(filename, titleMem, TITLE_LENGTH);

	dumpMemory("title_postsave.bin", titlePtr, 0x80);

	// Failure
	return 0;
}
*/

// loadCarFile(filename: char*): Int
// Given a filename, loads the data from
// the car file into memory. 
static int loadCarFile(char* filename)
{
	// Open the file with the filename
	FILE* file = fopen(filename, "rb");

	// File open OK
	if (file)
	{
		// Get the length of the file
		fseek(file, 0, SEEK_END);
		int fsize = ftell(file);

		// If the file has the right size
		if (fsize == 0xFF)
		{
			// Reset to start of the file and read it into the car data variable
			fseek(file, 0, SEEK_SET);
			fread(carDataDxp, fsize, 1, file);

			// Dereference the memory location for the car save data
			uintptr_t carSaveLocation = *(uintptr_t*)((*(uintptr_t*)(imageBaseDxp + saveLocation)) + 0x268);

			// Dev: Dump 100 bytes from the car save address every 30 seconds
			// watchMemory("car_watch", carSaveLocation, 0x100, 30);

			// memcpy((void*)(carSaveLocation + 0x00), carDataDxp + 0x00, 8); // Crash (Pointer)
			// memcpy((void*)(carSaveLocation + 0x08), carDataDxp + 0x08, 8); // ??
			// memcpy((void*)(carSaveLocation + 0x10), carDataDxp + 0x10, 8); // Crash (Pointer)
			// memcpy((void*)(carSaveLocation + 0x18), carDataDxp + 0x18, 8); // ??

			// memcpy((void*)(carSaveLocation + 0x20), carDataDxp + 0x20, 8); // Crash (Pointer)
			memcpy((void*)(carSaveLocation + 0x28), carDataDxp + 0x28, 8); // Region (0x28)
			memcpy((void*)(carSaveLocation + 0x30), carDataDxp + 0x30, 8); // CarID (0x34)
			// memcpy((void*)(carSaveLocation + 0x38), carDataDxp + 0x38, 4); // Stock Colour (0x38)
			memcpy((void*)(carSaveLocation + 0x3C), carDataDxp + 0x3C, 4); // CustomColor (0x3C)

			memcpy((void*)(carSaveLocation + 0x40), carDataDxp + 0x40, 8); // Rims (0x40), Rims Colour (0x44)
			memcpy((void*)(carSaveLocation + 0x48), carDataDxp + 0x48, 8); // Aero (0x48), Hood (0x4C)
			// memcpy((void*)(carSaveLocation + 0x50), carDataDxp + 0x50, 8); // Crash (Pointer)
			memcpy((void*)(carSaveLocation + 0x58), carDataDxp + 0x58, 8); // Wing (0x58), Mirror (0x5C)

			memcpy((void*)(carSaveLocation + 0x60), carDataDxp + 0x60, 8); // Sticker (0x60), Sticker Type (0x64)
			// memcpy((void*)(carSaveLocation + 0x68), carDataDxp + 0x60, 8); // Crash (Pointer)
			memcpy((void*)(carSaveLocation + 0x70), carDataDxp + 0x70, 8); // ?? 
			memcpy((void*)(carSaveLocation + 0x78), carDataDxp + 0x78, 8); // ?? 

			memcpy((void*)(carSaveLocation + 0x80), carDataDxp + 0x80, 8); // ??
			memcpy((void*)(carSaveLocation + 0x88), carDataDxp + 0x88, 8); // Roof Sticker (0x88), Roof Sticker Type (0x8C)
			memcpy((void*)(carSaveLocation + 0x90), carDataDxp + 0x90, 8); // Neon (0x90), Trunk (0x94)
			memcpy((void*)(carSaveLocation + 0x98), carDataDxp + 0x98, 8); // Plate Frame (0x98), Plate Frame Colour (0x9C) (??)

			memcpy((void*)(carSaveLocation + 0xA0), carDataDxp + 0xA0, 8); // Plate Number (0xA0), vinyl_body_challenge_prefecture_1~15 (0xA4)
			memcpy((void*)(carSaveLocation + 0xA8), carDataDxp + 0xA8, 8); // vinyl_body_challenge_prefecture (0xA8), Power (0xAC)
			// memcpy((void*)(carSaveLocation + 0xB0), carDataDxp + 0xB0, 8); // Crash (Title Pointer) (B0)
			memcpy((void*)(carSaveLocation + 0xB8), carDataDxp + 0xB8, 8); // Handling (0xB8), Rank (0xBC)

			// Example for setting license plate number to 4 20:
			// memset((void*)(carSaveLocation + 0xA1), 0x01, 0x1);
			// memset((void*)(carSaveLocation + 0xA0), 0xA4, 0x1);

			memcpy((void*)(carSaveLocation + 0xC0), carDataDxp + 0xC0, 8); // Window Sticker Toggle (0xC0)
			// memcpy((void*)(carSaveLocation + 0xC8), carDataDxp + 0xC8, 8); // Crash (Pointer)
			memcpy((void*)(carSaveLocation + 0xD0), carDataDxp + 0xD0, 8); // Window Sticker Value (0xD4)
			memcpy((void*)(carSaveLocation + 0xD8), carDataDxp + 0xD8, 8); // Versus Market (0xDC)

			// memcpy((void*)(carSaveLocation + 0xE0), carDataDxp + 0xE0, 8); // Crash (Pointer)
			// memcpy((void*)(carSaveLocation + 0xE8), carDataDxp + 0xE8, 8); // Crash (Pointer)
			memcpy((void*)(carSaveLocation + 0xF0), carDataDxp + 0xF0, 8); // ??
			// memcpy((void*)(carSaveLocation + 0xF8), carDataDxp + 0xF8, 8); // Crash (Region Pointer) (F8)
		}

		// Disable loading
		loadOkDxp = false;

		// Close the file
		fclose(file);

		// Success
		return  1;
	}

	// Failed
	return 0;
}

// loadCarData(filepath: char*): Void
// Given a filepath, attempts to load a 
// car file (either custom.car or specific
// car file) from that folder.
static int loadCarData(char * filepath)
{
	// Custom car disabled by default
	customCarDxp = false;

	// Miles path string
	char carPath[0xFF];

	// Set the milepath memory to zero
	memset(carPath, 0, 0xFF);

	// Copy the file path to the miles path
	strcpy(carPath, filepath);

	// Append the mileage filename to the string
	strcat(carPath, "\\OpenParrot_Cars");

	// Create the OpenParrot_cars directory at the given filepath
	std::filesystem::create_directories(carPath);

	// Get the path to the custom car file
	sprintf(carFileNameDxp, "%s\\custom.car", carPath);

	// If the custom car file exists
	if (FileExists(carFileNameDxp))
	{
		// Get the path to the title file
		sprintf(titleFileNameDxp, "%s\\custom.title", carPath);

		// Get the path to the name file
		sprintf(nameFileNameDxp, "%s\\custom.name", carPath);

		// Load the custom car file
		loadCarFile(carFileNameDxp);

		// Enable custom car switch
		customCarDxp = true;
	}
	else // Custom car file does not exist
	{
		// Empty the car filename string
		memset(carFileNameDxp, 0, 0xFF);

		// Get the path to the specific car file
		sprintf(carFileNameDxp, "%s\\%08X.car", carPath, selectedCarCodeDxp);

		// Get the path to the name file
		sprintf(nameFileNameDxp, "%s\\%08X.name", carPath, selectedCarCodeDxp);

		// Get the path to the specific car title file
		sprintf(titleFileNameDxp, "%s\\%08X.title", carPath, selectedCarCodeDxp);

		// If the specific car file exists
		if (FileExists(carFileNameDxp))
		{
			// Load the car file
			loadCarFile(carFileNameDxp);
		}
	}

	// Load the custom title file
	loadCustomTitle(titleFileNameDxp);

	// Load the custom name file
	loadCustomName(nameFileNameDxp);

	// If the force full tune switch is set
	if (ToBool(config["Tune"]["Force Full Tune"]))
	{
		// Set the car to be fully tuned
		setFullTune();
	}

	// Success
	return 1;
}

static int saveCarData(char* filepath)
{
	// Car Profile saving
	memset(carDataDxp, 0, 0xFF);
	memset(carFileNameDxp, 0, 0xFF);

	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(saveDataBase + 0x268);

	// Miles path string
	char carPath[0xFF];

	// Set the milepath memory to zero
	memset(carPath, 0, 0xFF);

	// Copy the file path to the miles path
	strcpy(carPath, filepath);

	// Append the mileage filename to the string
	strcat(carPath, "\\OpenParrot_Cars");

	// CreateDirectoryA(carPath, nullptr);

	// Create the cars path folder
	std::filesystem::create_directories(carPath);

	// Copy the 0xFF bytes from memory to the car data array
	memcpy(carDataDxp + 0x00, (void*)carSaveBase, 0xFF);

	// carFileNameDxp

	// If custom car is set
	if (customCarDxp)
	{
		// Save the file to custom.car
		sprintf(carFileNameDxp, "%s\\custom.car", carPath);

		// Save the title to custom.title
		sprintf(titleFileNameDxp, "%s\\custom.title", carPath);
	}
	else // Custom car is not set
	{
		// Save the file to the specific car filename
		sprintf(carFileNameDxp, "%s\\%08X.car", carPath, selectedCarCodeDxp);

		// Save the title to the specific car title
		sprintf(titleFileNameDxp, "%s\\%08X.title", carPath, selectedCarCodeDxp);
	}

	// Open the file at the given car path
	FILE* carFile = fopen(carFileNameDxp, "wb");

	// Write the data from the array to the file
	fwrite(carDataDxp, 1, 0xFF, carFile);
	fclose(carFile);

	// Save the title to the file
	// saveTitleFile(titleFileNameDxp);

	// Success
	return 1;
}

// loadStoryData(filepath: char *): Void
// Given a filepath, loads the story data 
// from the file into memory.
static int loadStoryData(char* filepath)
{
	// Zero out the save data array
	memset(saveDatadxp, 0x0, 0x2000);

	// Miles path string
	char storyPath[0xFF];

	// Set the milepath memory to zero
	memset(storyPath, 0, 0xFF);

	// Copy the file path to the miles path
	strcpy(storyPath, filepath);

	// Append the mileage filename to the string
	strcat(storyPath, "\\openprogress.sav");

	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Story save data offset
	uintptr_t saveStoryBase = *(uintptr_t*)(saveDataBase + 0x108);

	// Open the openprogress file with read privileges	
	FILE* file = fopen(storyPath, "rb");

	// If the file exists
	if (file)
	{
		// Get all of the contents from the file
		fseek(file, 0, SEEK_END);

		// Get the size of the file
		int fsize = ftell(file);

		// Check file is correct size
		if (fsize == 0x2000)
		{
			// Reset seek index to start
			fseek(file, 0, SEEK_SET);

			// Read all of the contents of the file into saveDatadxp
			fread(saveDatadxp, fsize, 1, file);

			// 0x00 - 08 4C - Should be able to use this to figure out what game a save is from

			// (Mostly) discovered story data

			memcpy((void*)(saveStoryBase + 0x48), saveDatadxp + 0x48, 0x8); // Story Bit
			memcpy((void*)(saveStoryBase + 0xE0), saveDatadxp + 0xE0, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0xE8), saveDatadxp + 0xE8, 0x8); // Chapter Progress (0xE8) (Bitmask)
			memcpy((void*)(saveStoryBase + 0xF0), saveDatadxp + 0xF0, 0x8); // Current Chapter (0xF0), Total Wins (0xF4)
			memcpy((void*)(saveStoryBase + 0xF8), saveDatadxp + 0xF8, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x100), saveDatadxp + 0x100, 0x8); // Win Streak (0x104)
			memcpy((void*)(saveStoryBase + 0x108), saveDatadxp + 0x108, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x110), saveDatadxp + 0x110, 0x8); // Locked Chapters (0x110) (Bitmask)
			
			// Can't tell if the data past this point does anything
			
			// memcpy((void*)(saveStoryBase + 0x118), saveDatadxp + 0x118, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x120), saveDatadxp + 0x120, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x128), saveDatadxp + 0x128, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x130), saveDatadxp + 0x130, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x138), saveDatadxp + 0x138, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x140), saveDatadxp + 0x140, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x148), saveDatadxp + 0x148, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x150), saveDatadxp + 0x150, 0x8); // ??
			// memcpy((void*)(saveStoryBase + 0x158), saveDatadxp + 0x158, 0x8); // ??

			// Save data loaded successfully
			loadOkDxp = true;

		}

		// Close the file
		fclose(file);
	}
	else // No story file
	{
		// If the start with 100 stories option is set
		if (ToBool(config["Story"]["Start at 60 Stories"]))
		{
			// Set total wins to 100
			memset((void*)(saveStoryBase + 0xF4), 0x3C, 0x1);

			// Set win streak to 100
			memset((void*)(saveStoryBase + 0x100), 0x3C, 0x1);

			// Set the current chapter to 5 (5 Chapters cleared)
			memset((void*)(saveStoryBase + 0xF0), 0x3, 0x1);
		}
	}

	// Success status
	return 1;
}

static int saveStoryData(char* filepath)
{
	// Miles path string
	char storyPath[0xFF];

	// Set the milepath memory to zero
	memset(storyPath, 0, 0xFF);

	// Copy the file path to the miles path
	strcpy(storyPath, filepath);

	// Append the mileage filename to the string
	strcat(storyPath, "\\openprogress.sav");

	// Save story data

	// Address where player save data starts
	uintptr_t saveDataBase = *(uintptr_t*)(imageBaseDxp + saveLocation);

	// Zero out save data binary
	memset(saveDatadxp, 0, 0x2000);

	// Address where the player story data starts
	uintptr_t storySaveBase = *(uintptr_t*)(saveDataBase + 0x108);

	// Copy to saveDatadxp from the story save data index
	memcpy(saveDatadxp, (void*)storySaveBase, 0x340);

	// Dump the save data to openprogress.sav
	writeDump(storyPath, saveDatadxp, 0x2000);

	// Success
	return 1;
}

static int loadMileData(char* filepath)
{
	// Zero out the mile data memory
	memset(mileDatadxp, 0, 0x08);

	// Miles path string
	char milepath[0xFF];

	// Set the milepath memory to zero
	memset(milepath, 0, 0xFF);

	// Copy the file path to the miles path
	strcpy(milepath, filepath);

	// Append the mileage filename to the string
	strcat(milepath, "\\mileage.dat");

	// Path to the miles file
	FILE* miles = fopen(milepath, "rb");
	
	// File loaded OK
	if (miles)
	{
		// Get the size of the file
		fseek(miles, 0, SEEK_END);
		int mileSize = ftell(miles);

		// If the file size is correct
		if (mileSize == 0x08)
		{
			// Load the content from the file into mileDatadxp
			fseek(miles, 0, SEEK_SET);
			fread(mileDatadxp, mileSize, 1, miles);

			// Get the pointer to the memory location storing the miles
			uintptr_t mileMemory = *(uintptr_t*)(imageBaseDxp + saveLocation);

			// Copy the mile data from the file into the memory location
			memcpy((void*)(mileMemory + 0x280), mileDatadxp + 0x00, 0x04);
		}
		// Close the miles file
		fclose(miles);
	}

	// Success
	return 1;
}

static int saveMileData(char* filepath)
{
	// Get the pointer to the memory location storing the miles
	auto mileageLocation = (uintptr_t*)(*(uintptr_t*)(imageBaseDxp + saveLocation) + 0x280);

	// Miles path string
	char milepath[0xFF];

	// Set the milepath memory to zero
	memset(milepath, 0, 0xFF);

	// Copy the file path to the miles path
	strcpy(milepath, filepath);

	// Append the mileage filename to the string
	strcat(milepath, "\\mileage.dat");

	// Load the miles file
	FILE* tempFile = fopen(milepath, "wb");

	// Write the miles data from memory to the miles file
	fwrite(mileageLocation, 1, sizeof(mileageLocation), tempFile);

	fclose(tempFile);

	// Success
	return 1;
}

// Credits to chery vtec tuning club for figuring out star loading / saving
static int saveVersusData(char* filepath)
{
	// Star path saving
	char starPath[0xFF];

	// Set the storyPath memory to zero
	memset(starPath, 0, 0xFF);

	// Copy the file path to the stars path
	strcpy(starPath, filepath);

	// Append the mileage filename to the string
	strcat(starPath, "\\openversus.sav");

	// Clear star data memory
	// memset(versusDataDxp, 0, 0x200);

	// Save Star Data

	// Dereference the versus pointer
	// Add 0x200 to it, because all of the versus stuff is after the first 0x200 bytes
	uintptr_t starBase = *(uintptr_t*)((*(uintptr_t*)(imageBaseDxp + saveLocation)) + 0x110) + 0x200;

	// Dumps first 2 bytes from star pointer
	// memcpy(versusDataDxp + 0x00, (void*)(starBase + 0x248), 0x4);
	
	// Dumps medal offsets from star pointer, 16 bytes
	// memcpy(versusDataDxp + 0x04, (void*)(starBase + 0x254), 0x10);

	// Dump the contents of the star data array to the file
	// writeDump(starPath, versusDataDxp, sizeof(versusDataDxp));
	dumpMemory(starPath, starBase, 0x100);

	// Success
	return 1;
}

static int loadVersusData(char* filepath)
{
	// Star path loading
	char versusPath[0xFF];

	// Set the storyPath memory to zero
	memset(versusPath, 0, 0xFF);

	// Copy the file path to the stars path
	strcpy(versusPath, filepath);

	// Append the mileage filename to the string
	strcat(versusPath, "\\openversus.sav");

	// Clear star data memory
	memset(versusDataDxp, 0, 0x100);

	// Open the star binary file
	FILE* starFile = fopen(versusPath, "rb");

	// Dereference the versus pointer in the game memory
	// Add 0x200 to it, because all of the versus stuff is after the first 0x200 bytes
	uintptr_t starBase = *(uintptr_t*)((*(uintptr_t*)(imageBaseDxp + saveLocation)) + 0x110) + 0x200;

	// Dev: Dump 100 bytes from the car save address every 30 seconds
	// watchMemory("versus_watch", starBase + 0x200, 0x100, 30);

	// If the file opened successfully
	if (starFile)
	{
		// If the file size is correct
		fseek(starFile, 0, SEEK_END);
		int starSize = ftell(starFile);
		if (starSize == 0x100)
		{
			// Reset the file pointer to the start
			fseek(starFile, 0, SEEK_SET);

			// Read all of the contents into the array
			fread(versusDataDxp, starSize, 1, starFile);

			// Dumps first 2 bytes from star pointer
			// memcpy((void*)(starBase + 0x248), versusDataDxp + 0x00, 0x4);

			// Dumps medal offsets from star pointer, 16 bytes
			// memcpy((void*)(starBase + 0x254), versusDataDxp + 0x04, 0x10);

			// Load the data from the versus region

			memcpy((void*)(starBase + 0x10), versusDataDxp + 0x10, 0x8); // ???
			memcpy((void*)(starBase + 0x18), versusDataDxp + 0x18, 0x8); // ???
			memcpy((void*)(starBase + 0x20), versusDataDxp + 0x20, 0x8); // Player Count (0x24)
			memcpy((void*)(starBase + 0x28), versusDataDxp + 0x28, 0x8); // ???
			
			memcpy((void*)(starBase + 0x30), versusDataDxp + 0x30, 0x8); // ???
			memcpy((void*)(starBase + 0x38), versusDataDxp + 0x38, 0x8); // Unknown 0x1 (0x8)
			memcpy((void*)(starBase + 0x40), versusDataDxp + 0x40, 0x8); // Win Streak (??)
			memcpy((void*)(starBase + 0x48), versusDataDxp + 0x48, 0x8); // Stars (0x48), ??? (0x4C)
			
			memcpy((void*)(starBase + 0x50), versusDataDxp + 0x50, 0x8); // Gold Medals (0x54) ??
			memcpy((void*)(starBase + 0x58), versusDataDxp + 0x58, 0x8); // Silver Medals (0x58), Bronze Medals (0x5C) ??
			memcpy((void*)(starBase + 0x60), versusDataDxp + 0x60, 0x8); // Black Medals (0x60)
			memcpy((void*)(starBase + 0x68), versusDataDxp + 0x68, 0x8); // ??
			
			memcpy((void*)(starBase + 0x70), versusDataDxp + 0x70, 0x8); // ??
			memcpy((void*)(starBase + 0x78), versusDataDxp + 0x78, 0x8); // ??
			memcpy((void*)(starBase + 0x80), versusDataDxp + 0x80, 0x8); // ??

			// Close the stars file
			fclose(starFile);
		}
	}

	// Success
	return 1;
}

static int loadGameData()
{
	// Disable saving
	saveOk = false;

	// Miles path string
	char loadPath[0xFF];

	// Set the milepath memory to zero
	memset(loadPath, 0, 0xFF);

	// Write the '.' into the load path
	// sprintf(loadPath, ".\\SaveData");
	sprintf(loadPath, ".");

	// Get the path to the selected car
	selectedCarCodeDxp = *(DWORD*)(*(uintptr_t*)(*(uintptr_t*)(imageBaseDxp + saveLocation) + 0x268) + 0x34);

	// Seperate save file / cars per user profile
	if (ToBool(config["Save"]["Save Per Custom Name"]))
	{
		// Get the profile name from the 
		std::string name = config["General"]["CustomName"];

		// Add the c string version of the profile name to the path
		sprintf(loadPath, "%s\\%s", loadPath, name.c_str());
	}

	// Seperate miles / story per car
	if (ToBool(config["Save"]["Save Per Car"]))
	{
		// Need to get the hex code for the selected car

		// If custom car is set
		if (customCarDxp)
		{
			// Add the car id to the save path
			sprintf(loadPath, "%s\\custom", loadPath);
		}
		else // Custom car is not set
		{
			// Add the custom folder to the save path
			sprintf(loadPath, "%s\\%08X", loadPath, selectedCarCodeDxp);
		}
	}

	// Ensure the directory exists
	std::filesystem::create_directories(loadPath);

	// Sleep for 1 second
	std::this_thread::sleep_for(std::chrono::seconds(1));

	// Load the car save file
	loadCarData(loadPath);

	// Load the openprogress.sav file
	loadStoryData(loadPath);

	// Load the miles save file
	loadMileData(loadPath);

	// Sleep for 30 seconds (Thanks Chery!)
	std::this_thread::sleep_for(std::chrono::seconds(30));

	// Load the stars save file
	loadVersusData(loadPath);

	// Success
	return 1;
}



// SaveGameData(void): Int
// If saving is enabled, loads the 
// player story data 
static int SaveGameData()
{
	// Saving is disabled
	if (!saveOk)
		return 1;

	// Miles path string
	char savePath[0xFF];

	// Set the milepath memory to zero
	memset(savePath, 0, 0xFF);

	// Wirte the '.' into the load path
	// sprintf(savePath, ".\\SaveData");
	sprintf(savePath, ".");

	// Seperate save file / cars per user profile
	if (ToBool(config["Save"]["Save Per Custom Name"]))
	{
		// Get the profile name from the 
		std::string name = config["General"]["CustomName"];

		// Add the c string version of the profile name to the path
		sprintf(savePath, "%s\\%s", savePath, name.c_str());
	}

	// Seperate miles / story per car
	if (ToBool(config["Save"]["Save Per Car"]))
	{
		// Need to get the hex code for the selected car

		// If custom car is set
		if (customCarDxp)
		{
			// Add the car id to the save path
			sprintf(savePath, "%s\\custom", savePath);
		}
		else // Custom car is not set
		{
			// Add the custom folder to the save path
			sprintf(savePath, "%s\\%08X", savePath, selectedCarCodeDxp);
		}
	}

	// Ensure the directory exists
	std::filesystem::create_directories(savePath);

	// Load the car save file
	saveCarData(savePath);

	// Load the openprogress.sav file
	saveStoryData(savePath);

	// Load the miles save file
	saveMileData(savePath);

	// Load the miles save file
	saveVersusData(savePath);

	// Disable saving
	saveOk = false;

	// Success
	return 1;
}

static void loadGame()
{
	// Runs after car data is loaded

	// Load story data thread
	std::thread t1(loadGameData);
	t1.detach();
}

static int ReturnTrue()
{
	return 1;
}

void GenerateDongleDataDxp(bool isTerminal)
{
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
}

static DWORD WINAPI SpamMulticast(LPVOID)
{
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
}

// Wmmt5Func([]()): InitFunction
// Performs the initial startup tasks for 
// maximum tune 5, including the starting 
// of required subprocesses.
static InitFunction Wmmt5Func([]()
{
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
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_write", dxpHook_hasp_write, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_read", dxpHook_hasp_read, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_get_size", dxpHook_hasp_get_size, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_decrypt", dxpHook_hasp_decrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_encrypt", dxpHook_hasp_encrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_logout", dxpHook_hasp_logout, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_106482.dll", "hasp_login", dxpHook_hasp_login, NULL);

	GenerateDongleDataDxp(isTerminal);

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
			CreateThread(0, 0, SpamMulticast, 0, 0, 0);
		}
	}
	/*
	else
	{
		// Patch some func to 1
		// 
		// FOUND ON 21, 10, 1
		// NOT FOUND:
		//safeJMP(imageBase + 0x7BE440, ReturnTrue);
		//safeJMP(hook::get_pattern("0F B6 41 05 2C 30 3C 09 77 04 0F BE C0 C3 83 C8 FF C3"), ReturnTrue);
		//safeJMP(imageBase + 0x89D420, ReturnTrue);

		// Patch some func to 1
		// 40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 28 48 8D ?? ?? ?? ?? 00 48 8D ?? ?? ?? ?? 00 41 B8 ?? ?? 00 00 FF 15 ?? ?? ?? ?? 4C 8B 1B 41 0F B6 43 78
		// FOUND ON 21, 10, 1
		//safeJMP(imageBase + 0x7CF8D0, ReturnTrue); 
		//safeJMP(hook::get_pattern("40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 11 48 8B 0D C2"), ReturnTrue);
		//safeJMP(imageBase + 0x8B5190, ReturnTrue); 
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
		// CreateThread(0, 0, spamCustomNameDxp, 0, 0, 0);
	}

	// Save story stuff (only 05)
	{
		// Enable all print
		injector::MakeNOP(imageBaseDxp + 0x898BD3, 6);

		// Load car and story data at once
		safeJMP(imageBaseDxp + 0x72AB90, loadGame);

		// Save car trigger
		// injector::WriteMemory<uintptr_t>(imageBase + 0x376F80 + 2, (uintptr_t)SaveGameData, true);
		// safeJMP(imageBase + 0x376F76, SaveGameData);

		// Save car trigger
		injector::MakeNOP(imageBaseDxp + 0x376F76, 0x12);
		injector::WriteMemory<WORD>(imageBaseDxp + 0x376F76, 0xB848, true);
		injector::WriteMemory<uintptr_t>(imageBaseDxp + 0x376F76 + 2, (uintptr_t)SaveGameData, true);
		injector::WriteMemory<DWORD>(imageBaseDxp + 0x376F80, 0x3348D0FF, true);
		injector::WriteMemory<WORD>(imageBaseDxp + 0x376F80 + 4, 0x90C0, true);

		// Prevents startup saving
		injector::WriteMemory<WORD>(imageBaseDxp + 0x6B909A, 0xB848, true);
		injector::WriteMemory<uintptr_t>(imageBaseDxp + 0x6B909A + 2, (uintptr_t)SaveOk, true);
		injector::WriteMemory<DWORD>(imageBaseDxp + 0x6B90A4, 0x9090D0FF, true);
	}

	MH_EnableHook(MH_ALL_HOOKS);

}, GameID::WMMT5DXPlus);
#endif
#pragma optimize("", on)