#pragma region imports

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

#pragma endregion

#pragma region globals

// If this is set, logging will be enabled
// and debug functions will be included in
// the compilation

// #define _DEBUG

#pragma region packets

// MUST DISABLE IC CARD, FFB MANUALLY N MT5DX+

// FOR FREEPLAY
uint8_t dxpterminalPackage1_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x12, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0xEC, 0x72, 0x00, 0x41
};

uint8_t dxpterminalPackage2_Free[139] = {
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

uint8_t dxpterminalPackage3_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x19, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x89, 0x93, 0x3A, 0x22
};

uint8_t dxpterminalPackage4_Free[139] = {
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

uint8_t dxpterminalPackage5_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x2F, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x9C, 0xC9, 0xE0, 0x73
};

uint8_t dxpterminalPackage6_Free[139] = {
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
uint8_t dxpterminalPackage1_Coin[75] = {
	0x01, 0x04, 0x47, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x0B, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x09,
	0x06, 0x41, 0x0B
};

uint8_t dxpterminalPackage2_Coin[135] = {
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

uint8_t dxpterminalPackage3_Coin[75] = {
	0x01, 0x04, 0x47, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x3A, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x22,
	0x25, 0x31, 0x0D
};

uint8_t dxpterminalPackage4_Coin[135] = {
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

uint8_t dxpterminalPackage5_Coin[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x58, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x3E, 0xB1, 0xB7, 0x22
};

uint8_t dxpterminalPackage6_Coin[139] = {
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
uint8_t dxpterminalPackage1_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xd1, 0x0b, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xc1, 0x96, 0xc9, 0x2e
};

uint8_t dxpterminalPackage2_Event4P[139] = {
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

uint8_t dxpterminalPackage3_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8d, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x86, 0xb1, 0x27, 0x9e
};

uint8_t dxpterminalPackage4_Event4P[139] = {
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

uint8_t dxpterminalPackage5_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xc9, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x5d, 0x49, 0x01, 0x1e
};

uint8_t dxpterminalPackage6_Event4P[139] = {
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
uint8_t dxpterminalPackage1_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xfe, 0x0e, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xaf, 0xa1, 0x42, 0x3d
};

uint8_t dxpterminalPackage2_Event2P[139] = {
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

uint8_t dxpterminalPackage3_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x80, 0x0f, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xa3, 0x94, 0x12, 0x9b
};

uint8_t dxpterminalPackage4_Event2P[139] = {
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

uint8_t dxpterminalPackage5_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8e, 0x0f, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xa3, 0xc2, 0x27, 0x9c
};

uint8_t dxpterminalPackage6_Event2P[139] = {
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

#pragma endregion

#pragma region constants

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

// Folder path for template files
#define TEMPLATE_FILEPATH "Templates"

// Log file for time attack match results
#define TA_CSV_FILENAME "timeattack.csv"

// Log file for versus match results
#define VS_CSV_FILENAME "versus.csv"


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

// GT Wing load/save size
#define GTWING_DATA_SIZE 0x30

// Car mini sticker load/save size
#define MINI_STICKER_DATA_SIZE 0xA4

// String File Lengths

// Maximum sticker length (32 bytes, 8 characters)
#define STICKER_LENGTH 0x10

// Maximum profile length name (255 characters)
#define PROFILE_LENGTH 0xFF

// Maximum region length (3 characters)
#define REGION_LENGTH 0x3

// Number of valid license plate regions
#define REGION_COUNT 0x2F

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

// *** uint8_t (Memory Storage) Objects ***

// Row which is used to end the sticker region
// Without this written to the sticker second row, 
// the sticker does not display.
uint8_t stringTerminator[0x10] = {
	0x0F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

// Car region codes
const char* regionCodesDxp[REGION_COUNT] = {
	"OCR", "ARG", "AUS", "AUT",
	"BHR", "BEL", "BRA", "BRN",
	"CAN", "CHL", "CHN", "DNK",
	"FIN", "FRA", "DEU", "HKG",
	"HUN", "IND", "IDN", "ITA",
	"JPN", "KOR", "MAC", "MYS",
	"MEX", "NLD", "NZL", "OMN",
	"PRY", "PER", "PHL", "QAT",
	"RUS", "SAU", "SGP", "ZAF",
	"ESP", "LKA", "CHE", "TWN",
	"THA", "TUR", "ARE", "GBR",
	"USA", "URY", "VNM"
};

#pragma endregion

#pragma region variables

// Car save data reserved memory
uint8_t carDataDxp[CAR_DATA_SIZE];

// Car code of the selected car (in the menu)
uint8_t selectedCarCodeDxp;

// *** Char Array (String) Variables ***

// Sticker filename string
char stickerFileNameDxp[FILENAME_MAX];

// Region filename string
char regionFileNameDxp[FILENAME_MAX];

// Title filename string
char titleFileNameDxp[FILENAME_MAX];

// Car name filename string
char nameFileNameDxp[FILENAME_MAX];

// Car filename string
char carFileNameDxp[FILENAME_MAX];

// GT Womg filename string
char gtWingFileNameDxp[FILENAME_MAX];

// Mini Sticker filename string
char miniStickFileNameDxp[FILENAME_MAX];

// User profile path (either 'CustomName' or '.')
char profilePath[FILENAME_MAX];

// General save path
char savePath[FILENAME_MAX];

// Car folder path
char carPath[FILENAME_MAX];

// Time attack csv path
char taCsvPath[FILENAME_MAX];

// Versus csv path
char vsCsvPath[FILENAME_MAX];

// Title string storage
char customTitleDxp[TITLE_LENGTH];

// Car name (i.e. G U E S T)
char carNameDxp[NAME_LENGTH];

// Custom name (i.e. Scrubbs)
char customNameDxp[PROFILE_LENGTH];

// *** Boolean Variables ***

// Sets if saving is allowed or not
static bool saveOk = false;

// Sets if TA / VS monitor threads should run
static bool watchTA = false;
static bool watchVS = false;

// Terminal emulator settings
static bool isFreePlay;
static bool isEventMode2P;
static bool isEventMode4P;

// Sets if loading is allowed
bool loadOkDxp = false;

// *** Misc. Variables ***

// Hook port
extern LPCSTR hookPort;

// Pointer to game memory
uintptr_t imageBaseDxp;

// Hasp buffer memory
static uint8_t hasp_buffer[0xD40];

// Network adapter IP Address
const char* ipaddrdxplus;

#pragma endregion

#pragma endregion

#pragma region hasp

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

unsigned int hook_hasp_encrypt(int hasp_handle, uint8_t* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_encrypt");
#endif
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_decrypt(int hasp_handle, uint8_t* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_decrypt");
#endif
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_get_size(int hasp_handle, int hasp_fileid, unsigned int* hasp_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_get_size");
#endif
	* hasp_size = 0xD40; // Max addressable size by the game... absmax is 4k
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_read(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, uint8_t* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_read");
#endif
	memcpy(buffer, hasp_buffer + offset, length);
	return HASP_STATUS_OK;
}

unsigned int hook_hasp_write(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, uint8_t* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_write");
#endif
	return HASP_STATUS_OK;
}
#pragma endregion

#pragma region time
// Set system date patch by pockywitch
typedef bool (WINAPI* SETSYSTEMTIME)(SYSTEMTIME* in);
SETSYSTEMTIME pSetSystemTime = NULL;

bool WINAPI Hook_SetSystemTime(SYSTEMTIME* in)
{
	return TRUE;
}

// Returns the current system time
static tm getCurrentTime()
{
	// Create a new std::time object
	auto t = std::time(nullptr);

	// Get the local system time
	auto time = *std::localtime(&t);

	// Return the time object
	return time;
}
#pragma endregion

#pragma region utility

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
			// Get the current system time
			tm currentTime = getCurrentTime();

			// Add the timestamp to the message
			eventLog << "[" << std::put_time(&currentTime, "%d-%m-%Y %H-%M-%S") << "] ";
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

// writeMemory(memory: uintptr_t, value: uint8_t, size: size_t, force: bool): Void
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

// writeDump(filename: Char*, data: uint8_t *, size: size_t): Int
// Given a filename, a data buffer pointer and a size dumps 'size' data
// from 'data' to the filename provided by 'filename'. This code is used
// for most of the saving routines, and is not just for dev purposes. 
// Returns a status code of 0 if successful, and a code of 1 if failed.
static int writeDump(char* filename, uint8_t* data, size_t size)
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
	uint8_t* data = (uint8_t*)malloc(size);

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
		memset(path, 0x0, FILENAME_MAX);

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

#pragma endregion

#pragma region time_attack

// saveTimeAttackData(filepath: char*): Int
// Given a filepath, saves the time attack data
// from the current play session to a file in 
// memory.
static int saveTimeAttackRecord()
{
#ifdef _DEBUG
	writeLog("Call to saveTimeAttackRecord...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where the  car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Address where the car settings data starts
	uintptr_t settingsSaveBase = *(uintptr_t*)(savePtr + SETTINGS_OFFSET);

	// Add the time attack offset to the story pointer
	uintptr_t timeAttackPtr = *(uintptr_t*)(savePtr + STORY_OFFSET) + 0x180;

	// Status code boolean
	bool status = 1;

	// Time Attack output stream
	std::ofstream taOfstream;

	// Open the time attack file for appending
	taOfstream.open(std::string(taCsvPath), std::ios_base::app);

	// If the filestream opens successfully
	if (taOfstream.is_open())
	{
		// Write the time attack data to a new row in the file

		// (Mostly) discovered time attack data
		// This is where the time attack data gets stored, BEFORE it gets cleared.
		// Unfortunately, we can't do much with this currently without finding out
		// where it gets stashed after the time attack screen ends.

		// Time Attack Offsets:
		// 0x188 - Final Time in Milliseconds
		// 0x18C - ??
		// 0x194 - Sector 1 time in ms
		// 0x198 - Sector 2 time in ms
		// 0x19C - Sector 3 time in ms
		// 0x1A0 - Sector 4 time in ms
		// 0x1A4 - Sector 5 time in ms (not verified)
		// 0x1A8 - Sector 6 time in ms (not verified)
		// 0x1AC - Sector 7 time in ms (not verified)
		// 0x1C0 - Pointer (??)
		// 0x1C8 - TA Games Played (This Session)
		// 0x1D8 - ??
		// 0x1DC - ??
		// 0x1E0 - ??
		// 0x1E4 - Course ID (enum)

		// Output Format:
		// 1. Game Code (e.g. wmmt5, wmmt5dxp, etc.)
		// 2. Time Submitted (time_t)
		// 3. Profile Name (e.g. Scrubbs)
		// 4. Car Name (e.g. G U E S T)
		// 5. Car Title (e.g. Wangan Beginner)
		// 6. Car Code (e.g. 0x7F = S2K)
		// 7. Car Rank (e.g. 0x0 = N)
		// 8. Car Region (e.g. 0x0 = OCR)
		// 9. Transmission (e.g. 0x0 = Auto)
		// 5. Course ID (e.g. 0x1 = C1 Inbound)
		// 6. Final Time
		// 7. Sector 1 (ms)
		// 8. Sector 2 (ms)
		// 9. Sector 3 (ms)
		// 10. Sector 4 (ms)
		// 11. Sector 5 (ms)
		// 12. Sector 6 (ms)
		// 13. Sector 7 (ms)

		// Get the car info from the car save region
		uint8_t carRegion = injector::ReadMemory<uint8_t>(carSaveBase + 0x28, true);
		uint8_t carCode = injector::ReadMemory<uint8_t>(carSaveBase + 0x34, true);
		uint8_t carRank = injector::ReadMemory<uint8_t>(carSaveBase + 0xBC, true); 

		// Get the settings info from the settings region
		uint8_t transmission = injector::ReadMemory<uint8_t>(settingsSaveBase + 0x0D, true); // Transmission offset

		// Get the course code from the time attack save region
		uint8_t courseCode = injector::ReadMemory<uint8_t>(timeAttackPtr + 0x0C, true); // Course selected

		// Sector times
		uint32_t sectors[8] = {

			// 0x188 - Final Time in Milliseconds
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x08, true),

			// 0x194 - Sector 1 time in ms
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x14, true),

			// 0x198 - Sector 2 time in ms
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x18, true),

			// 0x198 - Sector 3 time in ms
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x1C, true),

			// 0x198 - Sector 4 time in ms
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x20, true),

			// 0x198 - Sector 5 time in ms
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x24, true),

			// 0x198 - Sector 6 time in ms
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x28, true),

			// 0x198 - Sector 7 time in ms
			injector::ReadMemory<uint32_t>(timeAttackPtr + 0x2C, true)
		};

		// Get the current system time
		tm currentTime = getCurrentTime();

		// Write the time to the stream
		taOfstream <<
			"wmmt5dxp," << // Game Code (e.g. wmmt5, wmmt5dxp, etc.)
			mktime(&currentTime) << "," << // Submitted time (local timezone)
			customNameDxp << "," << // Profile Name (e.g. Scrubbs)
			carNameDxp << "," << // Car Name (e.g. G U E S T)
			customTitleDxp << "," << // Car Title (e.g. Wangan Beginner)
			std::to_string(carCode) << "," << // Car Code (e.g. 0x7F)
			std::to_string(carRank) << "," << // Car Rank (e.g. 0x0 = N)
			std::to_string(carRegion) << "," << // Car Region (e.g. 0x0 = OCR)
			std::to_string(transmission) << "," << // Transmission (e.g. 0x0 = Auto)
			std::to_string(courseCode) << "," << // Course ID (e.g. 0x1 = C1 Inbound)
			sectors[0] << "," << // Final time (milliseconds)
			sectors[1] << "," << // Sector 1 (milliseconds)
			sectors[2] << "," << // Sector 2 (milliseconds)
			sectors[3] << "," << // Sector 3 (milliseconds)
			sectors[4] << "," << // Sector 4 (milliseconds)
			sectors[5] << "," << // Sector 5 (milliseconds)
			sectors[6] << "," << // Sector 6 (milliseconds)
			sectors[7] << std::endl; // Sector 7 (milliseconds)

		// Success status
		status = 0;
	}

#ifdef _DEBUG
	status ? writeLog("saveTimeAttackRecord failed.") : writeLog("saveTimeAttackRecord success.");
#endif

	// Return status code
	return status;
}

// watchTmeAttack(LPVOID): DWORD WINAPI
// Watches the time attack region to see
// if a time has been written to memory. 
// If a time is detected, it is saved to
// the times.csv file.
static DWORD WINAPI watchTimeAttack(LPVOID)
{
#ifdef _DEBUG
	writeLog("Call to watchTimeAttack...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Story save data offset + Time Attack offset + Final Time offset
	uintptr_t finalTimePtr = *(uintptr_t*)(savePtr + STORY_OFFSET) + 0x180 + 0x08;

	// Get the final time
	uint32_t finalTime;

	// Last saved time
	uint32_t lastSavedTime = 0;

	// Records if the time has 
	// already been saved or not
	bool saved = false;

	// Infinite loop
	while (true)
	{
		// If TA is being logged
		if (watchTA)
		{
			// Get the current integer value at the final time offset
			finalTime = injector::ReadMemory<uint32_t>(finalTimePtr, true);

			// If the final time is set
			if (finalTime != 2147483647)
			{
				// If it does not match the last saved time
				if (finalTime != lastSavedTime)
				{
					// If the time has not been saved yet
					if (!saved)
					{
						// Call the save function
						saveTimeAttackRecord();

						// Update the last saved time
						lastSavedTime = finalTime;

						// Set saved to true
						saved = true;

						// No need to run again for at least another ~2 minutes
						std::this_thread::sleep_for(std::chrono::minutes(2));

						// Should prevent duplicate insertions
					}
				}
			}
			else // Final time is not set
			{
				// Set saved to false
				saved = false;
			}
		}

		// Wait for 'delay' milliseconds before checking again
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	}

#ifdef _DEBUG
	writeLog("watchTimeAttack done.");
#endif
}

#pragma endregion

#pragma region load_save

#pragma region cars

#pragma region tune

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
	auto powerAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase)+0xAC); // Power offset
	auto handleAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase)+0xB8); // Handling offset

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

#pragma endregion

#pragma region car_pointers

#pragma region custom_sticker

// saveCustomSticker(filename: char*): Int
// Given a filename, saves the default custom name
// attribute to the file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int saveCustomSticker()
{
#ifdef _DEBUG
	writeLog("Call to saveCustomSticker...");
#endif

	// Status code (default: Not created)
	bool status = 1;

	// If it does not exist, create the folder for template files
	std::filesystem::create_directories(TEMPLATE_FILEPATH);

	// Dump the default name to the file
	char path[FILENAME_MAX];
	sprintf(path, "%s\\custom.sticker", TEMPLATE_FILEPATH);

	// If the file does not exist, create the sample custom name
	if (!FileExists(path))
	{
		// Success status for the custom sticker dump
		status = writeDump(path, stringTerminator, STICKER_LENGTH);
	}

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
static int loadCustomSticker()
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

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.sticker", carPath, selectedCarCodeDxp);

	// Car-specific file exists
	if (!FileExists(path))
	{
		// Get the path to the profile-specific file
		sprintf(path, "%s\\custom.sticker", profilePath);

		// Profile-specific file exists
		if (!FileExists(path))
		{
			// Do not load the file
			file_exists = false;
		}
	}

	// If either the profile or car 
	// specific files were found
	if (file_exists)
	{
		// Open the file with the file name
		FILE* file = fopen(path, "rb");

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
	else // No files exist
	{
		// Save sample custom name file
		saveCustomSticker();
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

#pragma endregion

#pragma region custom_name

// saveCustomName(filename: char*): Int
// Given a filename, saves the default custom name
// attribute to the file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int saveCustomName()
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

	// Status code (default: Not created)
	bool status = 1;

	// If it does not exist, create the folder for template files
	std::filesystem::create_directories(TEMPLATE_FILEPATH);

	// Dump the default name to the file
	char path[FILENAME_MAX];
	sprintf(path, "%s\\custom.name", TEMPLATE_FILEPATH);

	// If the file does not exist, create the sample custom name
	if (!FileExists(path))
	{
		// Success status for the custom sticker dump
		status = dumpMemory(path, namePtr, NAME_LENGTH);
	}

#ifdef _DEBUG
	status ? writeLog("saveCustomName not saved.") : writeLog("saveCustomName saved.");
#endif

	// Return status code
	return status;
}

// loadCustomName(filename: char*): Int
// Given a filename, loads the default custom name
// attribute from the file. If the file does not
// exist, it is created using saveCustomName. 
// Returns true on a successful execution.
static int loadCustomName()
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

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.name", carPath, selectedCarCodeDxp);

	// Car-specific file doesn't exist
	if (!FileExists(path))
	{
		// Get the path to the profile-specific file
		sprintf(path, "%s\\custom.name", profilePath);

		// Profile-specific file doesn't exist
		if (!FileExists(path))
		{
			// Do not load the file
			file_exists = false;
		}
	}

	// If either the profile or car 
	// specific files were found
	if (file_exists)
	{
		// Open the file with the file name
		FILE* file = fopen(path, "rb");

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
	else // No files exist
	{
		// Save sample custom name file
		saveCustomName();
	}

	// Copy the name of the car into the car name variable
	memcpy(carNameDxp, (void*)namePtr, NAME_LENGTH);

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomName success.");
		break;
	case 1: // No file
		writeLog("loadCustomName failed: No file.");
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

#pragma endregion

#pragma region custom_gt_wing

// saveCustomGTWing(filename: char*): Int
// Given a filename, saves the default custom 
// GT wing data to the file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int saveCustomGTWing()
{
#ifdef _DEBUG
	writeLog("Call to saveCustomGTWing...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t gtWingPtr = *(uintptr_t*)(carSaveBase + 0x50);

	// Status code (default: Not created)
	bool status = 1;

	// If it does not exist, create the folder for template files
	std::filesystem::create_directories(TEMPLATE_FILEPATH);

	// Dump the default name to the file
	char path[FILENAME_MAX];
	sprintf(path, "%s\\custom.gtwing", TEMPLATE_FILEPATH);

	// If the file does not exist, create the sample custom name
	if (!FileExists(path))
	{
		// Success status for the custom sticker dump
		status = dumpMemory(path, gtWingPtr, GTWING_DATA_SIZE);
	}

#ifdef _DEBUG
	status ? writeLog("saveCustomGTWing failed.") : writeLog("saveCustomGTWing success.");
#endif

	// Return status code
	return status;
}

// loadCustomGTWing(filename: char*): Int
// Given a filename, loads the custom GT wing
// attribute from the file. If the file does not
// exist, it is created using saveCustomGTWing. 
// Returns true on a successful execution.
static int loadCustomGTWing()
{
#ifdef _DEBUG
	writeLog("Call to loadCustomGTWing...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t gtWingPtr = *(uintptr_t*)(carSaveBase + 0x50);

	// Success status (default: Failed to open file)
	int status = 1;

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.gtwing", carPath, selectedCarCodeDxp);

	// Car-specific file exists
	if (!FileExists(path))
	{
		// Get the path to the profile-specific file
		sprintf(path, "%s\\custom.gtwing", profilePath);

		// Profile-specific file exists
		if (!FileExists(path))
		{
			// Do not load the file
			file_exists = false;
		}
	}

	// If either the profile or car 
	// specific files were found
	if (file_exists)
	{
		// Open the file with the file name
		FILE* file = fopen(path, "rb");

		// File is opened successfully
		if (file)
		{
			// Get the length of the file
			fseek(file, 0, SEEK_END);
			int fsize = ftell(file);

			// If the file has the right size
			if (fsize == GTWING_DATA_SIZE)
			{
				// Reset to start of the file 
				// and read it into the car 
				// data variable
				fseek(file, 0, SEEK_SET);

				// Array for storing gt wing data temporarily
				unsigned char gtWingData[GTWING_DATA_SIZE];

				// Zero out the gt wing data storage
				memset(gtWingData, 0x0, GTWING_DATA_SIZE);

				// Copy the contents from the file into the storage
				fread(gtWingData, 0x1, GTWING_DATA_SIZE, file);

				// Memcpys for the gt wing data will go here :)
				memcpy((void*)(gtWingPtr + 0x10), (void*)(gtWingData + 0x10), 0x10); // Entire of row 2
				memcpy((void*)(gtWingPtr + 0x20), (void*)(gtWingData + 0x20), 0x10); // Entire of row 3

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
	else // No files exist
	{
		// Save sample custom name file
		saveCustomGTWing();
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomGTWing success.");
		break;
	case 1: // No file
		writeLog("loadCustomGTWing failed: No file. Default file created.");
		break;
	case 2: // File wrong size
		writeLog("loadCustomGTWing failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadCustomGTWing failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

#pragma endregion

#pragma region mini_sticker

// saveCustomGTWing(filename: char*): Int
// Given a filename, saves the default custom 
// GT wing data to the file. Returns a status code 
// of 0 if successful, and a code of 1 if failed.
static int saveCustomMiniSticker()
{
#ifdef _DEBUG
	writeLog("Call to saveCustomMiniSticker...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t miniStickerPtr = *(uintptr_t*)(carSaveBase + 0x68);

	// Create the mini sticker buffer
	uint8_t miniStickerData[MINI_STICKER_DATA_SIZE];

	// Zero out the mini sticker buffer
	memset(miniStickerData, 0x0, MINI_STICKER_DATA_SIZE);

	// Status code (default: Not created)
	bool status = 1;

	// If it does not exist, create the folder for template files
	std::filesystem::create_directories(TEMPLATE_FILEPATH);

	// Dump the default name to the file
	char path[FILENAME_MAX];
	sprintf(path, "%s\\custom.ministicker", TEMPLATE_FILEPATH);

	// If the file does not exist, create the sample custom name
	if (!FileExists(path))
	{
		// Loop over all of the mini stickers
		for (int i = 0; i < 10; i++)
		{
			// Get the offset to the current sticker
			int offset = i * 0x8;

			// Get the offset to the save address
			int save_offset = i * 0x10;

			// Get the pointer to the current sticker
			uintptr_t currentStickerPtr = *(uintptr_t*)(miniStickerPtr + offset);

			// Copy the the second row from the current mini sticker pointer to the 'i'th row in the buffer
			memcpy((void*)(miniStickerData + save_offset), (void*)(currentStickerPtr + 0x10), 0x10);
		}

		// Write 0xA0 -> 0xA4 from the mini sticker pointer to the save data
		memcpy((void*)(miniStickerData + 0xA0), (void*)(miniStickerPtr + 0x50), 0x4);

		// Success status for the custom sticker dump
		status = writeDump(path, miniStickerData, MINI_STICKER_DATA_SIZE);
	}

#ifdef _DEBUG
	status ? writeLog("saveCustomMiniSticker not saved.") : writeLog("saveCustomMiniSticker saved.");
#endif

	// Return status code
	return status;
}

// loadCustomGTWing(filename: char*): Int
// Given a filename, loads the custom GT wing
// attribute from the file. If the file does not
// exist, it is created using saveCustomGTWing. 
// Returns true on a successful execution.
static int loadCustomMiniSticker()
{
#ifdef _DEBUG
	writeLog("Call to loadCustomMiniSticker...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t miniStickerPtr = *(uintptr_t*)(carSaveBase + 0x68);

	// Success status (default: Failed to open file)
	int status = 1;

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.ministicker", carPath, selectedCarCodeDxp);

	// Car-specific file exists
	if (!FileExists(path))
	{
		// Get the path to the profile-specific file
		sprintf(path, "%s\\custom.ministicker", profilePath);

		// Profile-specific file exists
		if (!FileExists(path))
		{
			// Do not load the file
			file_exists = false;
		}
	}

	// If either the profile or car 
	// specific files were found
	if (file_exists)
	{
		// Open the file with the file name
		FILE* file = fopen(path, "rb");

		// File is opened successfully
		if (file)
		{
			// Get the length of the file
			fseek(file, 0, SEEK_END);
			int fsize = ftell(file);

			// If the file has the right size
			if (fsize == MINI_STICKER_DATA_SIZE)
			{
				// Reset to start of the file 
				// and read it into the car 
				// data variable
				fseek(file, 0, SEEK_SET);

				// Array for storing gt wing data temporarily
				unsigned char miniStickerData[MINI_STICKER_DATA_SIZE];

				// Zero out the gt wing data storage
				memset(miniStickerData, 0x0, MINI_STICKER_DATA_SIZE);

				// Copy the contents from the file into the storage
				fread(miniStickerData, 0x1, MINI_STICKER_DATA_SIZE, file);

				// Loop over all of the mini stickers
				for (int i = 0; i < 10; i++)
				{
					// Get the offset to the current sticker
					int offset = i * 0x8;

					// Get the offset to the save address
					int save_offset = i * 0x10;

					// Get the pointer to the current sticker
					uintptr_t currentStickerPtr = *(uintptr_t*)(miniStickerPtr + offset);

					// Copy the 'i'th row in the buffer to the second row from the current mini sticker pointer
					memcpy((void*)(currentStickerPtr + 0x10), (void*)(miniStickerData + save_offset), 0x10);
				}

				// Write 0xA0 -> 0xA4 from the save data to the mini sticker pointer
				memcpy((void*)(miniStickerPtr + 0x50), (void*)(miniStickerData + 0xA0), 0x4);

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
	else // File does not exist
	{
		// Create the custom mini sticker template file
		saveCustomMiniSticker();
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomMiniSticker success.");
		break;
	case 1: // No file
		writeLog("loadCustomMiniSticker failed: No file. Default file created.");
		break;
	case 2: // File wrong size
		writeLog("loadCustomMiniSticker failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadCustomMiniSticker failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

#pragma endregion

#pragma region custom_title

// saveCustomTitle(filepath: char*): Int
// Saves the custom title value to the current car's title, 
// otherwise creates a default title.
static int saveCustomTitle()
{
#ifdef _DEBUG
	writeLog("Call to saveCustomTitle...");
#endif

	// Create the title array
	char title[TITLE_LENGTH];

	// Empty the title array
	memset(title, 0x0, TITLE_LENGTH);

	// Write the default title to the string
	sprintf(title, "Wangan Beginner");

	// Status code (Default fail)
	bool status = 1;

	// If it does not exist, create the folder for template files
	std::filesystem::create_directories(TEMPLATE_FILEPATH);

	// Dump the default name to the file
	char path[FILENAME_MAX];
	sprintf(path, "%s\\custom.name", TEMPLATE_FILEPATH);

	// If the file does not exist, create the sample custom name
	if (!FileExists(path))
	{
		// Open the file for the title
		FILE* file = fopen(path, "w+");

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
	}

#ifdef _DEBUG
	status ? writeLog("saveCustomTitle not saved.") : writeLog("saveCustomTitle saved.");
#endif

	// Return status code
	return status;
}

// loadCustomTitle(filepath: char*): Int
// Loads the title string from the title file for the given car.
static int loadCustomTitle()
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

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.title", carPath, selectedCarCodeDxp);

	// Car-specific file exists
	if (!FileExists(path))
	{
		// Get the path to the profile-specific file
		sprintf(path, "%s\\custom.title", profilePath);

		// Profile-specific file exists
		if (!FileExists(path))
		{
			// Do not load the file
			file_exists = false;
		}
	}

	// If either the profile or car 
	// specific files were found
	if (file_exists)
	{
		// Open the file with the file name
		FILE* file = fopen(path, "rb");

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

				// Empty the title array
				memset(customTitleDxp, 0x0, TITLE_LENGTH);

				// Read the string content from the file
				fread(customTitleDxp, 0x1, TITLE_LENGTH, file);

				// Empty the existing title content
				memset((void*)titlePtr, 0x0, TITLE_LENGTH);

				// Write the new title to the string value
				memcpy((void*)titlePtr, customTitleDxp, TITLE_LENGTH);

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

	// If failure status is set
	if (status > 0)
	{
		// Copy the default title into the custom title variable
		memcpy(customTitleDxp, (void*)titlePtr, TITLE_LENGTH);

		// Save sample custom name file
		saveCustomTitle();
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomTitle success.");
		break;
	case 1: // No file
		writeLog("loadCustomTitle failed: No file. Template file created.");
		break;
	case 2: // File wrong size
		writeLog("loadCustomTitle failed: Wrong file size. Template file created.");
		break;
	default: // Generic error
		writeLog("loadCustomTitle failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

#pragma endregion

#pragma region custom_region

// saveCustomRegion(filepath: char*): Int
// Saves the custom title value to the current car's title, 
// otherwise creates a default title.
static int saveCustomRegion()
{
#ifdef _DEBUG
	writeLog("Call to saveCustomRegion...");
#endif

	// Status code (Default fail)
	bool status = 1;

	// Create the region array
	char region[REGION_LENGTH];

	// Empty the region array
	memset(region, 0x0, REGION_LENGTH);

	// Write the default region to the string
	sprintf(region, "JPN");

	// If it does not exist, create the folder for template files
	std::filesystem::create_directories(TEMPLATE_FILEPATH);

	// Dump the default name to the file
	char path[FILENAME_MAX];
	sprintf(path, "%s\\custom.region", TEMPLATE_FILEPATH);

	// If the file does not exist, create the sample custom name
	if (!FileExists(path))
	{
		// Open the file for the region
		FILE* file = fopen(path, "w+");

		// File is opened successfully
		if (file)
		{
			// Write the region string to the file
			fwrite((void*)region, 1, REGION_LENGTH, file);

			// Close the file handle
			fclose(file);

			// Success
			status = 0;
		}
	}

#ifdef _DEBUG
	status ? writeLog("saveCustomRegion not saved.") : writeLog("saveCustomRegion saved.");
#endif

	// Return status code
	return status;
}

// loadCustomTitle(filepath: char*): Int
// Loads the title string from the title file for the given car.
static int loadCustomRegion()
{
#ifdef _DEBUG
	writeLog("Call to loadCustomRegion...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Address where the title is saved
	uintptr_t regionPtr = *(uintptr_t*)(carSaveBase + 0xF8);

	// Success status (default: Failed to open file)
	int status = 1;

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.region", carPath, selectedCarCodeDxp);

	// Car-specific file exists
	if (!FileExists(path))
	{
		// Get the path to the profile-specific file
		sprintf(path, "%s\\custom.region", profilePath);

		// Profile-specific file exists
		if (!FileExists(path))
		{
			// Do not load the file
			file_exists = false;
		}
	}

	// If either the profile or car 
	// specific files were found
	if (file_exists)
	{
		// Open the file with the file name
		FILE* file = fopen(path, "rb");

		// File is opened successfully
		if (file)
		{
			// Get the length of the file
			fseek(file, 0, SEEK_END);
			int fsize = ftell(file);

			// If the file has the right size
			if (fsize == REGION_LENGTH)
			{
				// Reset to start of the file 
				// and read it into the car 
				// data variable
				fseek(file, 0, SEEK_SET);

				// Title string storage
				char region[REGION_LENGTH];

				// Empty the title array
				memset(region, 0x0, REGION_LENGTH);

				// Read the string content from the file
				fread(region, 0x1, REGION_LENGTH, file);

				// If the region code is not JPN
				if (strcmp(region, "JPN") != 0)
				{
					// Default: 0x14 (JPN)
					uint8_t region_id = 0x14;

					// Loop over all of the regions in the list
					for (int i = 0; i < REGION_COUNT; i++)
					{
						// If the region loaded matches the region
						if (strcmp(region, regionCodesDxp[i]) == 0)
						{
							// Set the region id to this offset
							region_id = i;

							// No need to keep looping, break
							break;
						}
					}

					// Set the player's license plate region to their custom region 
					memset((void*)(carSaveBase + 0x28), region_id, 0x1);
				}

				// Empty the existing title content
				memset((void*)regionPtr, 0x0, REGION_LENGTH);

				// Write the new title to the string value
				memcpy((void*)regionPtr, region, REGION_LENGTH);

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
	else // No files exist
	{
		// Save sample custom name file
		saveCustomRegion();
	}

#ifdef _DEBUG
	switch (status)
	{
	case 0: // Success
		writeLog("loadCustomRegion success.");
		break;
	case 1: // No file
		writeLog("loadCustomRegion failed: No file. Default file created.");
		break;
	case 2: // File wrong size
		writeLog("loadCustomRegion failed: Wrong file size.");
		break;
	default: // Generic error
		writeLog("loadCustomRegion failed.");
		break;
	}
#endif

	// Return status code
	return status;
}

#pragma endregion

#pragma endregion

#pragma region car_main

// verifyCarData(void): Int
// Compares the data in the loaded car data to the 
// data which is to be saved, to ensure that the new data
// has not been corrupted. This has been implemented as 
// a fix for a bug which was overwriting save files with
// junk data after entering the test menu during versus mode.
static int verifyCarData()
{
#ifdef _DEBUG
	writeLog("Call to verifyCarData...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Array which stores the offsets which should
	// be loaded and their purpose for car data.
	uint8_t offsets[] = {

		0x08, 0x0C, 0x10, 0x14,
		0x18, 0x1C, 0x24, 0x28,
		0x2C, 0x30, 0x34, 0x3C,
		0x40, 0x44, 0x48, 0x4C,
		0x54, 0x58, 0x5C, 0x60,
		0x64, 0x6C, 0x70, 0x78,
		0x7C, 0x80, 0x84, 0x88,
		0x8C, 0x90, 0x94, 0x98,
		0x9C, 0xA0, 0xA4, 0xA8,
		0xAC, 0xB4, 0xB8, 0xBC,
		0xC0, 0xC4, 0xD0, 0xD4,
		0xD8, 0xDC, 0xE0, 0xE4,
		0xEC, 0xF0, 0xF4, 0xFC
	};

	// Function validation status (default: invalid)
	bool status = 1;

	// Get the number of items in the offsets list
	uint32_t count = sizeof(offsets) / sizeof(*offsets);

	// Get the total value of the element(s)
	// If this is greater than zero, the car will be saved
	// If it is less than zero, it will not be saved
	int total = 0;

	// Loop over all of the offsets
	for (int i = 0; i < count; i++)
	{
		// Get the offset from the list
		uint8_t offset = offsets[i];

		// Get the current value in memory for the offset
		uint32_t value = injector::ReadMemory<uint32_t>(carSaveBase + offset);

		// Add the value to the total
		total += value;
	}

	// If the total is greater than zero
	if (total > 0)
	{
		// Car has not been zeroed, save ok
		status = 0;
	}
	else // Total is not greater than zero
	{
		// Car has been zeroed, save not ok

		// In the exceptional circumstance that
		// a car could have this result genuinely, 
		// there would be no consequences to not 
		// saving its data anyway (as there is no 
		// relevant data to save).

		// Status remains 1
	}

#ifdef _DEBUG
	status ? writeLog("verifyCarData validation failed.") : writeLog("verifyCarData validation success.");
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

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

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
	else // File not loaded
	{
		// Dump the current car memory to carDataDxp
		memcpy((void*)carDataDxp, (void*)carSaveBase, CAR_DATA_SIZE);
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

static int saveCarData()
{
#ifdef _DEBUG
	writeLog("Call to saveCarData...");
#endif

	memset(carFileNameDxp, 0, FILENAME_MAX);

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBaseDxp + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Save the file to the specific car filename
	sprintf(carFileNameDxp, "%s\\%08X.car", carPath, selectedCarCodeDxp);

	// Success status for the custom car file dump
	bool status = dumpMemory(carFileNameDxp, carSaveBase, CAR_DATA_SIZE);

#ifdef _DEBUG
	status ? writeLog("saveCarData failed.") : writeLog("saveCarData success.");
#endif

	// Return status code
	return status;
}

// loadCarData(filepath: char*): Void
// Given a filepath, attempts to load a 
// car file (either custom.car or specific
// car file) from that folder.
static int loadCarData()
{
#ifdef _DEBUG
	writeLog("Call to loadCarData...");
#endif

	// Car file load success status
	bool status = false;

	// Get the path to the specific car file
	sprintf(carFileNameDxp, "%s\\%08X.car", carPath, selectedCarCodeDxp);

	// If the specific car file exists
	if (FileExists(carFileNameDxp))
	{
		// Load the car file
		status = loadCarFile(carFileNameDxp);
	}

	// Attempt to load custom files

	loadCustomName();
	loadCustomTitle();
	loadCustomGTWing();
	loadCustomRegion();
	loadCustomSticker();
	loadCustomMiniSticker();

	// If the force full tune switch is set
	if (ToBool(config["Save"]["Force Full Tune"]))
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
#pragma endregion

#pragma endregion

#pragma region settings

static int saveSettingsData()
{
#ifdef _DEBUG
	writeLog("Call to saveSettingData...");
#endif

	// Miles path string
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", savePath, SETTINGS_FILENAME);

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

static int loadSettingsData()
{
#ifdef _DEBUG
	writeLog("Call to loadSettingsData...");
#endif

	// Save data dump memory block
	uint8_t settingsData[SETTINGS_DATA_SIZE];

	// Zero out the save data array
	memset(settingsData, 0x0, SETTINGS_DATA_SIZE);

	// Miles path string
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", savePath, SETTINGS_FILENAME);

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
		saveSettingsData();
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

#pragma endregion

#pragma region story

static int saveStoryData()
{
#ifdef _DEBUG
	writeLog("Call to saveStoryData...");
#endif

	// Miles path string
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", savePath, STORY_FILENAME);

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

// loadStoryData(filepath: char *): Void
// Given a filepath, loads the story data 
// from the file into memory.
static int loadStoryData()
{
#ifdef _DEBUG
	writeLog("Call to loadStoryData...");
#endif

	// Save data dump memory block
	uint8_t storyDataDxp[STORY_DATA_SIZE];

	// Zero out the save data array
	memset(storyDataDxp, 0x0, STORY_DATA_SIZE);

	// Miles path string
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	sprintf(path, "%s\\%s", savePath, STORY_FILENAME);

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

					// If we have done all of the other chapters
					if ((storyDataDxp[0xEC] & 0xE0) == 0xE0)
					{
						// Clear the locked final chapter
						storyDataDxp[0x111] &= ~(0x2);
					}

					// Fix the story tune (to make up for the skipped chapter)
					fixStoryTune();
				}
			}

			// 0x00 - 08 4C - Should be able to use this to figure out what game a save is from

			// (Mostly) discovered story data

			memcpy((void*)(saveStoryBase + 0x48), storyDataDxp + 0x48, 0x8); // Story Bit
			memcpy((void*)(saveStoryBase + 0xE0), storyDataDxp + 0xE0, 0x8); // Story Play Count (0xE0)
			memcpy((void*)(saveStoryBase + 0xE8), storyDataDxp + 0xE8, 0x8); // Tuning Points (0xE8), Chapter Progress Bitmask (0xEC)
			memcpy((void*)(saveStoryBase + 0xF0), storyDataDxp + 0xF0, 0x8); // Current Chapter (0xF0), Total Wins (0xF4)
			memcpy((void*)(saveStoryBase + 0xF8), storyDataDxp + 0xF8, 0x8); // Lose bits (0xF4) (??), Lose (0xF8) (??)
			memcpy((void*)(saveStoryBase + 0x100), storyDataDxp + 0x100, 0x8); // Win Streak (0x104)
			memcpy((void*)(saveStoryBase + 0x108), storyDataDxp + 0x108, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x110), storyDataDxp + 0x110, 0x8); // Locked Chapters (0x110) (Bitmask)

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
		if (ToBool(config["Save"]["Start at 60 Stories"]))
		{
			// Set total wins to 60
			memset((void*)(saveStoryBase + 0xF4), 0x3C, 0x1);

			// Set win streak to 60
			memset((void*)(saveStoryBase + 0x104), 0x3C, 0x1);

			// Set the current chapter to 3 (3 Chapters cleared)
			memset((void*)(saveStoryBase + 0xF0), 0x3, 0x1);

			// Offsets for the locked chapter bitmask
			memset((void*)(saveStoryBase + 0x110), 0x10, 0x1); // Chapter 5 locked
			memset((void*)(saveStoryBase + 0x111), 0x42, 0x1); // Chapters 10, 15 locked
			memset((void*)(saveStoryBase + 0x112), 0x08, 0x1); // Chapter 20 locked
			memset((void*)(saveStoryBase + 0x113), 0x00, 0x1); // Empty space
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

#pragma endregion

#pragma region miles

static int saveMileData()
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

	// Append the mileage filename to the string
	// strcat(path, "\\openprogress.sav");
	sprintf(path, "%s\\%s", savePath, MILE_FILENAME);

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

static int loadMileData()
{
#ifdef _DEBUG
	writeLog("Call to loadMileData...");
#endif

	// Mile data dump memory block
	uint8_t mileData[MILE_DATA_SIZE];

	// Zero out the mile data memory
	memset(mileData, 0x0, MILE_DATA_SIZE);

	// Miles path string
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	sprintf(path, "%s\\%s", savePath, MILE_FILENAME);

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
			memcpy((void*)mileMemory, mileData, 0x8);

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

#pragma endregion

#pragma region versus

// Credits to chery vtec tuning club for figuring out star loading / saving
static int saveVersusData()
{
#ifdef _DEBUG
	writeLog("Call to saveVersusData...");
#endif

	// Star path saving
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	// strcat(path, "\\openversus.sav");
	sprintf(path, "%s\\%s", savePath, VERSUS_FILENAME);

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

static int loadVersusData()
{
#ifdef _DEBUG
	writeLog("Call to loadVersusData...");
#endif

	// Star data dump memory block
	uint8_t versusData[VERSUS_DATA_SIZE];

	// Clear star data memory
	memset(versusData, 0, VERSUS_DATA_SIZE);

	// Star path loading
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	sprintf(path, "%s\\%s", savePath, VERSUS_FILENAME);

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

#pragma endregion

#pragma region game

// saveGameData(void): Int
// If saving is enabled, loads the 
// player story data 
static int saveGameData()
{
#ifdef _DEBUG
	writeLog("Call to saveGameData...");
#endif

	// Success/fail code (default: fail)
	int status = 1;

	// If saving is enabled, 
	// and the car data is verified
	if (saveOk && (verifyCarData() == 0))
	{
		// Load the car save file
		saveCarData();

		// Load the openprogress.sav file
		saveStoryData();

		// Load the miles save file
		saveMileData();

		// Load the miles save file
		saveVersusData();

		// Disable saving
		saveOk = false;

		// Success
		status = 0;
	}

#ifdef _DEBUG
	status ? writeLog("saveGameData failed.") : writeLog("saveGameData success.");
#endif

	// Success
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

	// Set the save path memory to zero
	memset(savePath, 0, FILENAME_MAX);

	// Set the profile path memory to zero
	memset(profilePath, 0, FILENAME_MAX);

	// Write the '.' into the load path
	sprintf(profilePath, ".");

	// Get the path to the selected car
	selectedCarCodeDxp = *(DWORD*)(*(uintptr_t*)(*(uintptr_t*)(imageBaseDxp + SAVE_OFFSET) + CAR_OFFSET) + 0x34);

	// Seperate save file / cars per user profile
	if (ToBool(config["Save"]["Save Per Custom Name"]))
	{
		// Add the c string version of the profile name to the path
		sprintf(profilePath, "%s\\%s", profilePath, customNameDxp);
	}

	// Seperate miles / story per car
	if (ToBool(config["Save"]["Save Per Car"]))
	{
		// Need to get the hex code for the selected car

		// Add the custom folder to the save path
		sprintf(savePath, "%s\\%08X", profilePath, selectedCarCodeDxp);
	}
	else // Combine miles / story per car
	{
		// Save path is same as profile path
		sprintf(savePath, "%s", profilePath);
	}

	// Set the car path memory to zero
	memset(carPath, 0, FILENAME_MAX);

	// Set the path to the cars folder
	sprintf(carPath, "%s\\%s", savePath, CAR_FILEPATH);

	// Create the directories recursively
	std::filesystem::create_directories(carPath);

	// Sleep for 1 second
	std::this_thread::sleep_for(std::chrono::seconds(1));

	// Load the car save file
	loadCarData();

	// Load the car settings file
	loadSettingsData();

	// Load the openprogress.sav file
	loadStoryData();

	// Load the miles save file
	loadMileData();

	// Generate path to the time attack csv file
	sprintf(taCsvPath, "%s\\%s", profilePath, TA_CSV_FILENAME);

	// If the time attack csv file exists
	if (FileExists(taCsvPath))
	{
		// Watch for TA data changes
		watchTA = true;
	}

	// Generate path to the versus csv file
	sprintf(vsCsvPath, "%s\\%s", profilePath, VS_CSV_FILENAME);

	// If the versus csv file exists
	if (FileExists(vsCsvPath))
	{
		// Watch for VS data changes
		watchVS = true;
	}

	// Check if the versus file exists

	// Sleep for 30 seconds (Thanks Chery!)
	std::this_thread::sleep_for(std::chrono::seconds(30));

	// Load the stars save file
	loadVersusData();

	// If at least one is set
	if (watchTA || watchVS)
	{
		// Start the time attack / versus monitor thread
		CreateThread(0, 0, watchTimeAttack, 0, 0, 0);
	}

#ifdef _DEBUG
	writeLog("loadGameData done.");
#endif

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

#pragma endregion

#pragma endregion

#pragma region misc

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

	if (isTerminal)
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

#pragma endregion

#pragma region main

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

			// Sets if the custom name should be spammed (over the nameplate)
			if (ToBool(config["General"]["SpamCustomName"]))
			{
				// Create the spam custom name thread
				CreateThread(0, 0, spamCustomName, 0, 0, 0);
			}
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
#pragma endregion