#pragma region imports

#define NOMINMAX

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

// Data for IC card, Force Feedback etc OFF.
unsigned char settingData[408] = {
	0x1F, 0x8B, 0x08, 0x08, 0x53, 0x6A, 0x8B, 0x5A, 0x00, 0x03, 0x46, 0x73,
	0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x2E, 0x6C, 0x75, 0x61, 0x00, 0x85,
	0x93, 0x5B, 0x6F, 0x82, 0x30, 0x14, 0xC7, 0xDF, 0xF9, 0x14, 0x7E, 0x01,
	0x17, 0x11, 0xE7, 0xDC, 0xC3, 0x1E, 0x14, 0x65, 0x9A, 0x48, 0x66, 0x94,
	0x68, 0xB2, 0xB7, 0x5A, 0x8E, 0xD2, 0xD8, 0x8B, 0x29, 0xED, 0x16, 0xBF,
	0xFD, 0x5A, 0xA8, 0x50, 0xB2, 0x65, 0xF2, 0x40, 0xF8, 0xFF, 0xCE, 0x85,
	0x73, 0x69, 0xFB, 0xFD, 0xFF, 0x9F, 0xC0, 0xBE, 0x7A, 0x25, 0x28, 0x45,
	0xF8, 0xF9, 0x89, 0x6A, 0x14, 0x3C, 0x08, 0xE8, 0x07, 0x01, 0x8B, 0x11,
	0x25, 0xC7, 0x25, 0xE2, 0x39, 0x85, 0x18, 0xB8, 0x02, 0xD9, 0x7B, 0xEB,
	0x45, 0xC3, 0x97, 0xF1, 0xC4, 0x99, 0xA6, 0x18, 0x03, 0x6D, 0x2C, 0x03,
	0x47, 0x67, 0x12, 0x5D, 0xE0, 0x17, 0x4D, 0x85, 0x12, 0xB2, 0xA1, 0xCF,
	0x61, 0xE8, 0x78, 0x26, 0x34, 0x2E, 0xD6, 0x70, 0x52, 0x86, 0x0E, 0x07,
	0xA3, 0x89, 0x8F, 0xB7, 0xE4, 0x5C, 0x58, 0x1E, 0x8E, 0xA2, 0x68, 0xEC,
	0x1B, 0x32, 0x71, 0xFD, 0x0B, 0xCF, 0x84, 0x52, 0x82, 0xB5, 0x89, 0x04,
	0xE1, 0x71, 0xA1, 0x15, 0x58, 0xDF, 0x80, 0xCD, 0xF4, 0x2D, 0x46, 0x32,
	0x8F, 0x45, 0x69, 0x73, 0x46, 0x01, 0x7B, 0x47, 0x0C, 0x9C, 0x1A, 0x5A,
	0x6F, 0x6E, 0x66, 0xA3, 0x3D, 0x92, 0x68, 0x4A, 0x63, 0xA1, 0x65, 0x79,
	0x67, 0x23, 0xC3, 0x24, 0xC0, 0x86, 0xA2, 0x5B, 0x9D, 0x72, 0x83, 0x8F,
	0xAB, 0xBC, 0x6E, 0x72, 0x85, 0x6D, 0xF2, 0xED, 0xB7, 0xAF, 0xF6, 0xC0,
	0xF3, 0xFB, 0x10, 0xD2, 0xB3, 0x6F, 0x4F, 0x84, 0xC4, 0x90, 0x00, 0xE4,
	0x47, 0x84, 0x2F, 0x35, 0x3A, 0x10, 0x5E, 0x4E, 0x79, 0xBE, 0x05, 0x86,
	0xCC, 0x57, 0x9D, 0x7F, 0xF1, 0x65, 0x06, 0x96, 0x8A, 0x1C, 0x6A, 0x97,
	0x46, 0xCE, 0x49, 0x55, 0x8F, 0x8F, 0x4C, 0xA1, 0xDC, 0xD5, 0x18, 0x53,
	0x51, 0x42, 0x76, 0xBB, 0x82, 0x6B, 0xCC, 0xCA, 0x9D, 0xE6, 0x46, 0xBD,
	0x8E, 0x9D, 0x4C, 0x45, 0x47, 0x66, 0x1A, 0x7C, 0x79, 0x80, 0xBC, 0x63,
	0x2D, 0xB4, 0x2F, 0x13, 0x49, 0x7C, 0xB9, 0x43, 0xCA, 0x97, 0xF3, 0x6A,
	0x36, 0x56, 0x56, 0x2B, 0xD9, 0x20, 0x0E, 0xB4, 0x2E, 0xD5, 0x8E, 0x7B,
	0x2F, 0xAC, 0x08, 0x8D, 0x9A, 0x2A, 0x25, 0x11, 0x56, 0x2D, 0xF8, 0x38,
	0x9D, 0x28, 0xE1, 0xD0, 0x76, 0x6B, 0xD2, 0xE1, 0x8B, 0xA1, 0xE6, 0xD0,
	0xD6, 0x20, 0x23, 0x0C, 0x3E, 0x05, 0xBF, 0xB7, 0x66, 0x77, 0x6F, 0x91,
	0xF9, 0xE3, 0xDA, 0x1D, 0x14, 0xCF, 0x69, 0x69, 0x16, 0xD7, 0x04, 0x4F,
	0x5A, 0x9E, 0x12, 0xEE, 0xE7, 0xDC, 0x69, 0xC6, 0x40, 0x5A, 0x63, 0x27,
	0xA0, 0x63, 0xE9, 0x86, 0x3C, 0xBC, 0x37, 0xD5, 0x4D, 0x5B, 0x7C, 0x24,
	0x8F, 0x3D, 0x7F, 0x00, 0x10, 0x1E, 0x34, 0xD9, 0xB5, 0x03, 0x00, 0x00
};

// FOR FREEPLAY
unsigned char terminalPackage1_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x12, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0xEC, 0x72, 0x00, 0x41
};

unsigned char terminalPackage2_Free[139] = {
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

unsigned char terminalPackage3_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x19, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x89, 0x93, 0x3A, 0x22
};

unsigned char terminalPackage4_Free[139] = {
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

unsigned char terminalPackage5_Free[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x2F, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x9C, 0xC9, 0xE0, 0x73
};

unsigned char terminalPackage6_Free[139] = {
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
unsigned char terminalPackage1_Coin[75] = {
	0x01, 0x04, 0x47, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x0B, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x09,
	0x06, 0x41, 0x0B
};

unsigned char terminalPackage2_Coin[135] = {
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

unsigned char terminalPackage3_Coin[75] = {
	0x01, 0x04, 0x47, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x00, 0x2A, 0x12, 0x08, 0x3A, 0x12, 0x0C, 0x32, 0x37,
	0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00,
	0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0B,
	0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x22,
	0x25, 0x31, 0x0D
};

unsigned char terminalPackage4_Coin[135] = {
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

unsigned char terminalPackage5_Coin[79] = {
	0x01, 0x04, 0x4B, 0x00, 0x12, 0x14, 0x0A, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x40, 0x00, 0x48, 0x00,
	0x50, 0x00, 0x1A, 0x02, 0x5A, 0x00, 0x2A, 0x12, 0x08, 0x58, 0x12, 0x0C,
	0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39, 0x39, 0x30, 0x30, 0x30, 0x32,
	0x18, 0x00, 0x30, 0x03, 0x4A, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x00,
	0x20, 0x00, 0x52, 0x0B, 0x08, 0x64, 0x10, 0xDE, 0x0F, 0x18, 0x05, 0x20,
	0x00, 0x28, 0x00, 0x3E, 0xB1, 0xB7, 0x22
};

unsigned char terminalPackage6_Coin[139] = {
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
unsigned char terminalPackage1_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xd1, 0x0b, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xc1, 0x96, 0xc9, 0x2e
};

unsigned char terminalPackage2_Event4P[139] = {
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

unsigned char terminalPackage3_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8d, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x86, 0xb1, 0x27, 0x9e
};

unsigned char terminalPackage4_Event4P[139] = {
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

unsigned char terminalPackage5_Event4P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xc9, 0x0c, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0x5d, 0x49, 0x01, 0x1e
};

unsigned char terminalPackage6_Event4P[139] = {
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
unsigned char terminalPackage1_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0xfe, 0x0e, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xaf, 0xa1, 0x42, 0x3d
};

unsigned char terminalPackage2_Event2P[139] = {
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

unsigned char terminalPackage3_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x80, 0x0f, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xa3, 0x94, 0x12, 0x9b
};

unsigned char terminalPackage4_Event2P[139] = {
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

unsigned char terminalPackage5_Event2P[79] = {
	0x01, 0x04, 0x44, 0x00, 0x12, 0x0e, 0x0a, 0x00, 0x10, 0x04, 0x18, 0x00,
	0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x38, 0x00, 0x1a, 0x00, 0x2a, 0x13,
	0x08, 0x8e, 0x0f, 0x12, 0x0c, 0x32, 0x37, 0x32, 0x32, 0x31, 0x31, 0x39,
	0x39, 0x30, 0x30, 0x30, 0x32, 0x18, 0x00, 0x30, 0x00, 0x4a, 0x08, 0x08,
	0x03, 0x10, 0x01, 0x18, 0x00, 0x20, 0x00, 0x52, 0x0b, 0x08, 0x64, 0x10,
	0xde, 0x0f, 0x18, 0x05, 0x20, 0x00, 0x28, 0x00, 0xa3, 0xc2, 0x27, 0x9c
};

unsigned char terminalPackage6_Event2P[139] = {
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

// **** Data Region Sizes

// Settings region load/save size
#define SETTINGS_DATA_SIZE 0x30

// Versus region load/save size
#define VERSUS_DATA_SIZE 0x100

// Story region load/save size
#define STORY_DATA_SIZE 0x2000

// Miles region load/save size
#define MILE_DATA_SIZE 0x8

// Car region load/save size
#define CAR_DATA_SIZE 0xE0

// GT Wing load/save size
#define GTWING_DATA_SIZE 0x1C

// Car mini sticker load/save size

// #define MINI_STICKER_DATA_SIZE 0xA0
#define MINI_STICKER_DATA_SIZE 0x50

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
#define SAVE_OFFSET 0x1948F10

// Settings Data Offset (Within Save Data Region)
#define SETTINGS_OFFSET 0x3A8

// Story Data Offset (Within Save Data Region)
#define STORY_OFFSET 0x108

// Mile Data Offset (Within Save Data Region)
#define MILE_OFFSET 0x250

// Car Data Offset (Within Save Data Region)
#define CAR_OFFSET 0x240

// *** uint8_t (Memory Storage) Objects ***

// Row which is used to end the sticker region
// Without this written to the sticker second row, 
// the sticker does not display.
static uint8_t stringTerminator[0x10] = {
	0x0F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0F, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

// Car region codes
static const char* regionCodes[REGION_COUNT] = {
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

// Car code of the selected car (in the menu)
static uint8_t selectedCarCode;

// Car save data reserved memory
static uint8_t carData[CAR_DATA_SIZE];

// *** Char Array (String) Variables ***

// Car filename string
static char carFileName[FILENAME_MAX];

// User profile path (either 'CustomName' or '.')
static char profilePath[FILENAME_MAX];

// General save path
static char savePath[FILENAME_MAX];

// Car folder path
static char carPath[FILENAME_MAX];

// Time attack csv path
static char taCsvPath[FILENAME_MAX];

// Car name (i.e. G U E S T)
static char carName[NAME_LENGTH];

// Custom name (i.e. Scrubbs)
static char customName[PROFILE_LENGTH];

// *** Boolean Variables ***

// Terminal emulator settings
static bool isFreePlay;
static bool isEventMode2P;
static bool isEventMode4P;

// Sets if loading is allowed
static bool loadOk = false;

// Sets if saving is allowed or not
static bool saveOk = false;

// Sets if TA thread is running or not
static bool taThread = false;

// *** Misc. Variables ***

// Hook port
extern LPCSTR hookPort;

// Base game memory address
static uintptr_t imageBase;

// Hasp buffer memory
static uint8_t hasp_buffer[0xD40];

// Network adapter IP Address
static const char* ipaddr;

#pragma endregion

#pragma endregion

#pragma region hasp

#define HASP_STATUS_OK 0
unsigned int Hook_hasp_login(int feature_id, void* vendor_code, int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_login\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int Hook_hasp_logout(int hasp_handle) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_logout\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int Hook_hasp_encrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_encrypt\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int Hook_hasp_decrypt(int hasp_handle, unsigned char* buffer, unsigned int buffer_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_decrypt\n");
#endif
	return HASP_STATUS_OK;
}

unsigned int Hook_hasp_get_size(int hasp_handle, int hasp_fileid, unsigned int* hasp_size) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_get_size\n");
#endif
	* hasp_size = 0xD40; // Max addressable size by the game... absmax is 4k
	return HASP_STATUS_OK;
}

unsigned int Hook_hasp_read(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
#ifdef _DEBUG
	OutputDebugStringA("hasp_read\n");
#endif
	memcpy(buffer, hasp_buffer + offset, length);
	return HASP_STATUS_OK;
}

unsigned int Hook_hasp_write(int hasp_handle, int hasp_fileid, unsigned int offset, unsigned int length, unsigned char* buffer) {
	return HASP_STATUS_OK;
}

typedef int (WINAPI* BIND)(SOCKET, CONST SOCKADDR*, INT);
BIND pbind = NULL;

unsigned int WINAPI Hook_bind(SOCKET s, const sockaddr* addr, int namelen) {
	sockaddr_in bindAddr = { 0 };
	bindAddr.sin_family = AF_INET;
	bindAddr.sin_addr.s_addr = inet_addr("192.168.96.20");
	bindAddr.sin_port = htons(50765);
	if (addr == (sockaddr*)&bindAddr) {
		sockaddr_in bindAddr2 = { 0 };
		bindAddr2.sin_family = AF_INET;
		bindAddr2.sin_addr.s_addr = inet_addr(ipaddr);
		bindAddr2.sin_port = htons(50765);
		return pbind(s, (sockaddr*)&bindAddr2, namelen);
	}
	else {
		return pbind(s, addr, namelen);

	}
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
static std::string logfile = "wmmt5_errors.txt";

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

// writeFullWidthChar(c: Char, target: uintptr_t)
// Given a standard character, 
static int writeFullWidthChar(char c, uintptr_t target)
{
#ifdef _DEBUG
	writeLog("Call to writeFullWidthChar...");
#endif

	// Status code (default: Not written)
	int status = 1;

	// If the char is within the acceptable range
	if (c > ' ' && c < 127)
	{
		// If the character is later than '-'
		if (c > '_')
		{
			// Set the memory address to the full-width char
			memset((void*)(target + 0x0), 0xEF, 0x1);
			memset((void*)(target + 0x1), 0xBD, 0x1);
			memset((void*)(target + 0x2), 0x20 + c, 0x1);
		}
		else // Character is earlier than '-'
		{
			// Set the memory address to the full-width char
			memset((void*)(target + 0x0), 0xEF, 0x1);
			memset((void*)(target + 0x1), 0xBC, 0x1);
			memset((void*)(target + 0x2), 0x60 + c, 0x1);
		}

		// Success status
		status = 0;
	}
	else // Character is out of range
	{
		// Write the standard char to the text
		memset((void*)(target + 0x00), c, 0x1);
	}

#ifdef _DEBUG
	status ? writeLog("writeFullWidthChar success.") : writeLog("writeFullWidthChar out of range.");
#endif

	// Return status code
	return status;
}

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where the  car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Address where the car settings data starts
	uintptr_t settingsSaveBase = *(uintptr_t*)(savePtr + SETTINGS_OFFSET);

	// Add the time attack offset to the story pointer
	uintptr_t timeAttackPtr = *(uintptr_t*)(savePtr + STORY_OFFSET) + 0x1B8;

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
		// 0x1B8 - Sector 6 time in ms (not verified)
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
		// 7. Car Rank (e.g. 0x1 = N)
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
		uint8_t carRegion = injector::ReadMemory<uint8_t>(carSaveBase + 0x20, true);
		uint32_t carTitle = injector::ReadMemory<uint32_t>(carSaveBase + 0xA0, true);
		uint8_t carCode = injector::ReadMemory<uint8_t>(carSaveBase + 0x2C, true);
		uint8_t carRank = injector::ReadMemory<uint8_t>(carSaveBase + 0xA4, true);

		// Get the settings info from the settings region
		uint8_t transmission = injector::ReadMemory<uint8_t>(settingsSaveBase + 0x15, true); // Transmission offset

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
			"wmmt5," << // Game Code (e.g. wmmt5, wmmt5dxp, etc.)
			mktime(&currentTime) << "," << // Submitted time (local timezone)
			customName << "," << // Profile Name (e.g. Scrubbs)
			carName << "," << // Car Name (e.g. G U E S T)
			std::to_string(carTitle) << "," << // Car Title (e.g. A3 1A 06)
			std::to_string(carCode) << "," << // Car Code (e.g. 0x7F)
			std::to_string(carRank) << "," << // Car Rank (e.g. 0x1 = N)
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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Story save data offset + Time Attack offset + Final Time offset
	uintptr_t finalTimePtr = *(uintptr_t*)(savePtr + STORY_OFFSET) + 0x1B8 + 0x8;

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

	// Car save hex address
	auto carSaveBase = (uintptr_t*)((*(uintptr_t*)(imageBase + SAVE_OFFSET)) + CAR_OFFSET);

	// Pointer to power, handling and rank offsets
	auto powerAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase) + 0x98);
	auto handleAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase) + 0x9C);
	auto rankAddress = (uintptr_t*)(*(uintptr_t*)(carSaveBase) + 0xA4);

	// Dereference the power, handling and rank values from memory
	auto powerValue = injector::ReadMemory<uint8_t>(powerAddress, true);
	auto handleValue = injector::ReadMemory<uint8_t>(handleAddress, true);
	auto rankValue = injector::ReadMemory<uint8_t>(rankAddress, true);

	// Success status (default: fail)
	bool update = 1;

	// If the power and handling values do not add up to fully tuned
	if (powerValue + handleValue < 0x20)
	{
		// Car is not fully tuned, force it to the default full tune
		injector::WriteMemory<uint8_t>(powerAddress, 0x10, true);
		injector::WriteMemory<uint8_t>(handleAddress, 0x10, true);

		// Rank is less than C4
		if (rankValue < 0x07)
		{
			// Set the rank to 0x07 (C4)
			injector::WriteMemory<uint8_t>(rankAddress, 0x07, true);
		}

		// Success status
		update = 0;
	}

#ifdef _DEBUG
	update ? writeLog("setFullTune not updated.") : writeLog("setFullTune updated.");
#endif

	// Return status code
	return update;
}

// forceFullTune(pArguments: void*): DWORD WINAPI
// Function which runs in a secondary thread if the forceFullTune
// option is selected in the compiler. If the player's car is not fully
// tuned, it is forcibly set to max tune. If the player's car is already
// fully tuned, it is left alone. 
static DWORD WINAPI forceFullTune(void* pArguments)
{
	// Loops while the program is running
	while (true) {

		// Sleep for 16ms
		Sleep(16);

		// Run the set full tune process
		setFullTune();
	}
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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Address where the window sticker is stored
	uintptr_t stickerPtr = *(uintptr_t*)(carSaveBase + 0xB0);

	// Success status (default: Failed to open file)
	int status = 1;

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.sticker", carPath, selectedCarCode);

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

				// Success
				status = 0;
			}
			else // Sticker file is wrong size
			{
				// Incorrect file size 
				status = 2;
			}

			// Close the file
			fclose(file);
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

// spamCustomNameThread(LPVOID): DWORD WINAPI
// Starts a thread which spams the 
static DWORD WINAPI spamCustomNameThread(LPVOID)
{
	// Pointer to the nameplate text memory address
	void* value = (void*)(imageBase + 0x1E19EE0);

	// Infinite loop
	while (true)
	{
		// Copy the custom name into the nameplate text
		memcpy(value, customName, strlen(customName) + 1);

		// Wait 50 milliseconds 
		Sleep(50);
	}
}

// spamCustomName(playerName: String): Int
// Given a string, starts a thread which spams that 
// string on the player's nameplate during runtime.
static int spamCustomName(std::string playerName)
{
#ifdef _DEBUG
	writeLog("Call to spamCustomName...");
#endif

	// Status code (default: Not started)
	int status = 1;

	// Clear the custom name array
	memset(customName, 0, PROFILE_LENGTH);

	// If a custom name is set
	if (!playerName.empty())
	{
		// Copy the custom name to the custom name array
		strcpy(customName, playerName.c_str());

		// If the temp name is greater than 5
		if (playerName.length() > 5)
		{
			// Create the spam custom name thread
			CreateThread(0, 0, spamCustomNameThread, 0, 0, 0);

			// Status code = 0 (thread started)
			status = 0;
		}

		// Status code = 2 (thread not started - too short)
		status = 2;
	}

	// Status code = 1 (thread not started - no text)

#ifdef _DEBUG
	switch (status)
	{
		// Thread Started
	case 0:
		writeLog("spamCustomName thread started!");
		break;

		// Thread Not Started (No Text)
	case 1:
		writeLog("spamCustomName thread not started! No text!");
		break;

		// Thread Not Started (Too Short)
	case 2:
		writeLog("spamCustomName thread not started! Text too short!");
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
static int saveCustomName()
{
#ifdef _DEBUG
	writeLog("Call to saveCustomName...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t namePtr = *(uintptr_t*)(carSaveBase + 0x18);

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t namePtr = *(uintptr_t*)(carSaveBase + 0x18);

	// File exists status
	bool file_exists = true;

	// Success status (default: Failed to open file)
	int status = 1;

	// Save sample custom name file
	saveCustomName();

	// Custom Name Specific Stuff

	// Get the custom name specified in the  config file
	std::string playerName = config["General"]["CustomName"];

	// Start the spam custom name thread
	spamCustomName(playerName);

	// Clear the default name pointer
	memset((void*)namePtr, 0x0, NAME_LENGTH);

	// Test for a car-specific name file

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.name", carPath, selectedCarCode);

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

				// Write the new title to the string value
				memcpy((void*)namePtr, name, NAME_LENGTH);

				// Success
				status = 0;
			}
			else // Name file is the wrong size
			{
				// Incorrect file size
				status = 2;
			}

			// Close the file
			fclose(file);
		}
	}
	else // No files exist
	{
		// Get the number of characters to write (max. 5)
		int length = std::min((int)(playerName.length()), 5);

		// Loop over all of the characters in the tekno player name
		for (int i = 0; i < length; i++)
		{
			// Write the full width character into the pointer
			writeFullWidthChar(playerName.at(i), namePtr + (i * 3));
		}
	}

	// Copy the name of the car into the car name variable
	memcpy(carName, (void*)namePtr, NAME_LENGTH);

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t gtWingPtr = *(uintptr_t*)(carSaveBase + 0x48);

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
		status = dumpMemory(path, gtWingPtr + 0x10, GTWING_DATA_SIZE);
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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t gtWingPtr = *(uintptr_t*)(carSaveBase + 0x48);

	// Success status (default: Failed to open file)
	int status = 1;

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.gtwing", carPath, selectedCarCode);

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
				memcpy((void*)(gtWingPtr + 0x10), (void*)(gtWingData), GTWING_DATA_SIZE); // Entire data

				// Success
				status = 0;
			}
			else // Name file is the wrong size
			{
				// Incorrect file size
				status = 2;
			}

			// Close the file
			fclose(file);
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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t miniStickerPtr = *(uintptr_t*)(carSaveBase + 0x60);

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

			// Get the pointer to the current sticker
			uintptr_t currentStickerPtr = *(uintptr_t*)(miniStickerPtr + offset);

			// Copy the the second row from the current mini sticker pointer to the 'i'th row in the buffer
			memcpy((void*)(miniStickerData + offset), (void*)(currentStickerPtr + 0x10), 0x8);
		}

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// _DEBUG: Address where the player name (might be) saved
	uintptr_t miniStickerPtr = *(uintptr_t*)(carSaveBase + 0x60);

	// Success status (default: Failed to open file)
	int status = 1;

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.ministicker", carPath, selectedCarCode);

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

					// Get the pointer to the current sticker
					uintptr_t currentStickerPtr = *(uintptr_t*)(miniStickerPtr + offset);

					// Copy the 'i'th row in the buffer to the second row from the current mini sticker pointer
					memcpy((void*)(currentStickerPtr + 0x10), (void*)(miniStickerData + offset), 0x8);
				}

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Address where the title is saved
	uintptr_t regionPtr = *(uintptr_t*)(carSaveBase + 0xD0);

	// Success status (default: Failed to open file)
	int status = 1;

	// File exists status
	bool file_exists = true;

	// Path to the file
	char path[FILENAME_MAX];
	memset(path, 0x0, FILENAME_MAX);

	// Test for a car-specific name file

	// Get the path to the car-specific file
	sprintf(path, "%s\\%08X.region", carPath, selectedCarCode);

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
						if (strcmp(region, regionCodes[i]) == 0)
						{
							// Set the region id to this offset
							region_id = i;

							// No need to keep looping, break
							break;
						}
					}

					// Set the player's license plate region to their custom region 
					memset((void*)(carSaveBase + 0x20), region_id, 0x1);
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
static int verifyCarData()
{
#ifdef _DEBUG
	writeLog("Call to verifyCarData...");
#endif

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Function validation status (default: invalid)
	dumpMemory("cardata.bin", carSaveBase, CAR_DATA_SIZE);

	// If there is no value at this offset, the save file is invalid
	bool status = (!((bool)(injector::ReadMemory<uint64_t>(carSaveBase))));

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Car Profile saving
	memset(carData, 0, CAR_DATA_SIZE);

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
			fread(carData, fsize, 1, file);

			// memcpy((void*)(carSaveBase + 0x18), carData + 0x18, 0x8); // Car Name (Pointer)
			memcpy((void*)(carSaveBase + 0x20), carData + 0x20, 0x8); // Plate Region (0x20)
			memcpy((void*)(carSaveBase + 0x28), carData + 0x28, 0x8); // Car ID (0x2C)
			// memcpy((void*)(carSaveBase + 0x30), carData + 0x30, 4); // Stock Colour (0x30)
			memcpy((void*)(carSaveBase + 0x34), carData + 0x34, 0x4); // Custom Colour (0x34)
			memcpy((void*)(carSaveBase + 0x38), carData + 0x38, 0x8); // Rims Type (0x38), Rims Colour (0x3C)

			memcpy((void*)(carSaveBase + 0x40), carData + 0x40, 0x8); // Aero Type (0x40), Hood Type (0x44)
			// memcpy((void*)(carSaveBase + 0x48), carData + 0x48, 0x8); // Custom GT Wing (Pointer)
			memcpy((void*)(carSaveBase + 0x50), carData + 0x50, 0x8); // Wing Type (0x50), Mirror Type (0x54)
			memcpy((void*)(carSaveBase + 0x58), carData + 0x58, 0x8); // Body Sticker Type (0x58), Japan Sticker Type (0x59), Variant (0x5C)

			// memcpy((void*)(carSaveBase + 0x60), carData + 0x60, 8); // Mini Stickers (Pointer)
			// memcpy((void*)(carSaveBase + 0x68), carData + 0x68, 0x8); // Don't touch this data
			memcpy((void*)(carSaveBase + 0x74), carData + 0x74, 0x8); // Side Sticker Type (0x74), Side Sticker Colour (0x78)
			memcpy((void*)(carSaveBase + 0x7C), carData + 0x7C, 0x4); // Neon Type (0x7C)

			// Example for setting license plate number to 4 20:
			// memset((void*)(carSaveBase + 0x8D), 0x01, 0x1);
			// memset((void*)(carSaveBase + 0x8C), 0xA4, 0x1);

			memcpy((void*)(carSaveBase + 0x80), carData + 0x80, 0x8); // Trunk Colour (0x80), Plate Frame (0x84), 1SP-3SP Frame (0x85-0x87)
			memcpy((void*)(carSaveBase + 0x88), carData + 0x88, 0x8); // Plate Frame Colour (0x8A), License Plate Number (0x8C)
			// memcpy((void*)(carSaveBase + 0x90), carData + 0x90, 0x8); // ?? (Probably empty space)
			memcpy((void*)(carSaveBase + 0x98), carData + 0x98, 0x8); // Power (0x98), Handling (0x9C)

			memcpy((void*)(carSaveBase + 0xA0), carData + 0xA0, 0x8); // Title (0xA0-0xA3), Rank (0xA4)
			memcpy((void*)(carSaveBase + 0xA8), carData + 0xA8, 0x4); // Team Sticker On/Off (0xA8)
			// memcpy((void*)(carSaveBase + 0xAC), carData + 0xAC, 0x4); // Team Sticker ID (Crash)

			// memcpy((void*)(carSaveBase + 0xB0), carData + 0xB0, 8); // Team Sticker Text (Pointer)
			memcpy((void*)(carSaveBase + 0xB8), carData + 0xB8, 4); // Team Sticker Font (0xB8)
			// memcpy((void*)(carSaveBase + 0xBC), carData + 0xBC, 4); // Last Played Date (0xBC)

			// memcpy((void*)(carSaveBase + 0xC0), carData + 0xC0, 8); // Last Played Location (Pointer) (??)
			memcpy((void*)(carSaveBase + 0xC8), carData + 0xC8, 0x8); // ??
			// memcpy((void*)(carSaveBase + 0xD0), carData + 0xD0, 8); // Region (Pointer)
			memcpy((void*)(carSaveBase + 0xD8), carData + 0xD8, 0x8); // ??

			// Success
			status = 0;
		}
		else // Car file is not the correct size
		{
			// Car file incorrect size code
			status = 2;
		}

		// Disable loading
		loadOk = false;

		// Close the file
		fclose(file);
	}
	else // File not loaded
	{
		// Dump the current car memory to carData
		memcpy((void*)carData, (void*)carSaveBase, CAR_DATA_SIZE);
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

	memset(carFileName, 0, FILENAME_MAX);

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

	// Address where car save data starts
	uintptr_t carSaveBase = *(uintptr_t*)(savePtr + CAR_OFFSET);

	// Save the file to the specific car filename
	sprintf(carFileName, "%s\\%08X.car", carPath, selectedCarCode);

	// Success status for the custom car file dump
	bool status = dumpMemory(carFileName, carSaveBase, CAR_DATA_SIZE);

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
	sprintf(carFileName, "%s\\%08X.car", carPath, selectedCarCode);

	// If the specific car file exists
	if (FileExists(carFileName))
	{
		// Load the car file
		status = loadCarFile(carFileName);
	}

	// Attempt to load custom files

	loadCustomName();
	loadCustomGTWing();
	loadCustomRegion();
	loadCustomSticker();
	loadCustomMiniSticker();

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

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

			// Read all of the contents of the file into storyData
			fread(settingsData, fsize, 1, file);

			memcpy((void*)(settingsPtr + 0x18), (void*)(settingsData + 0x18), 0x8); // Second row (second half)
			memcpy((void*)(settingsPtr + 0x20), (void*)(settingsData + 0x20), 0x10); // Third row (entire row)

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
		// Big if-else block for the different meter settings

		if (strcmp(config["General"]["Custom Meter"].c_str(), "White Meter") == 0)
			memset((void*)(settingsPtr + 0x18), 0x1, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Yellow Meter") == 0)
			memset((void*)(settingsPtr + 0x18), 0x2, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Red Meter") == 0)
			memset((void*)(settingsPtr + 0x18), 0x3, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Special Meter") == 0)
			memset((void*)(settingsPtr + 0x18), 0x4, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Blue Meter") == 0)
			memset((void*)(settingsPtr + 0x18), 0x5, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Carbon Meter") == 0)
			memset((void*)(settingsPtr + 0x18), 0x6, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Metallic Meter (Black)") == 0)
			memset((void*)(settingsPtr + 0x18), 0x7, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Metallic Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x18), 0x8, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Cyber Meter (Blue)") == 0)
			memset((void*)(settingsPtr + 0x18), 0x9, 0x1);
		else if (strcmp(config["General"]["Custom Meter"].c_str(), "Cyber Meter (Red)") == 0)
			memset((void*)(settingsPtr + 0x18), 0xA, 0x1);
	}

	// If a non-default custom soundtrack is selected in the drop-down
	if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "Default") != 0)
	{
		// Not sure if I can clean this up, this is just how the MT6 code does the neons

		// Big if-else block for the different soundtrack settings

		if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "Maximum Tune 3/DX/DX+") == 0)
			memset((void*)(settingsPtr + 0x20), 0x1, 0x1);
		else if (strcmp(config["General"]["Custom Soundtrack"].c_str(), "10 Outrun") == 0)
			memset((void*)(settingsPtr + 0x20), 0x2, 0x1);
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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

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
	uint8_t storyData[STORY_DATA_SIZE];

	// Zero out the save data array
	memset(storyData, 0x0, STORY_DATA_SIZE);

	// Miles path string
	char path[FILENAME_MAX];

	// Append the mileage filename to the string
	sprintf(path, "%s\\%s", savePath, STORY_FILENAME);

	// Address where player save data starts
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

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

			// Read all of the contents of the file into saveData
			fread(storyData, fsize, 1, file);

			// 0x00 - 70 23 - Should be able to use this to figure out what game a save is from

			// (Mostly) discovered story data

			memcpy((void*)(saveStoryBase + 0x118), storyData + 0x118, 0x8); // Total Wins (0x118)
			memcpy((void*)(saveStoryBase + 0x120), storyData + 0x120, 0x8); // Chapter Progress (0x120) (Bitmask), Current Chapter (0x124)
			memcpy((void*)(saveStoryBase + 0x128), storyData + 0x128, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x130), storyData + 0x130, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x138), storyData + 0x138, 0x8); // Win Streak (0x138)
			memcpy((void*)(saveStoryBase + 0x140), storyData + 0x140, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x148), storyData + 0x148, 0x8); // ??
			memcpy((void*)(saveStoryBase + 0x150), storyData + 0x150, 0x8); // Locked Chapters (0x150) (Bitmask)
			memcpy((void*)(saveStoryBase + 0x158), storyData + 0x158, 0x8); // ??

			// Save data loaded successfully
			loadOk = true;

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
		// If the start with 100 stories option is set
		if (ToBool(config["Save"]["Start at 60 Stories"]))
		{
			// Set total wins to 100
			memset((void*)(saveStoryBase + 0x118), 0x3C, 0x1);

			// Set win streak to 100
			memset((void*)(saveStoryBase + 0x138), 0x3C, 0x1);

			// Set the current chapter to 5 (5 Chapters cleared)
			memset((void*)(saveStoryBase + 0x124), 0x3, 0x1);
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
	uintptr_t savePtr = *(uintptr_t*)(imageBase + SAVE_OFFSET);

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
			uintptr_t mileMemory = *(uintptr_t*)(imageBase + SAVE_OFFSET) + MILE_OFFSET;

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
	uintptr_t versusPtr = *(uintptr_t*)((*(uintptr_t*)(imageBase + SAVE_OFFSET)) + 0x110) + 0x234;

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
	uintptr_t versusPtr = *(uintptr_t*)((*(uintptr_t*)(imageBase + SAVE_OFFSET)) + 0x110) + 0x234;

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

static int SaveGameData()
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
		// Ensure the directory exists
		std::filesystem::create_directories(savePath);

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

	// Disable saving
	saveOk = false;

	// Set the save path memory to zero
	memset(savePath, 0, FILENAME_MAX);

	// Set the profile path memory to zero
	memset(profilePath, 0, FILENAME_MAX);

	// Write the '.' into the load path
	sprintf(profilePath, ".");

	// Get the path to the selected car
	selectedCarCode = *(DWORD*)(*(uintptr_t*)(*(uintptr_t*)(imageBase + SAVE_OFFSET) + CAR_OFFSET) + 0x2C);

	// Seperate save file / cars per user profile
	if (ToBool(config["Save"]["Save Per Custom Name"]))
	{
		// Add the c string version of the profile name to the path
		sprintf(profilePath, "%s\\%s", profilePath, customName);
	}

	// Seperate miles / story per car
	if (ToBool(config["Save"]["Save Per Car"]))
	{
		// Need to get the hex code for the selected car

		// Add the custom folder to the save path
		sprintf(savePath, "%s\\%08X", profilePath, selectedCarCode);
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

	// If the time attack thread has not been started
	// and the time attack file exists
	if ((!taThread) && FileExists(taCsvPath))
	{
		// Start the time attack / versus monitor thread
		CreateThread(0, 0, watchTimeAttack, 0, 0, 0);

		// TA thread has been started
		taThread = true;
	}

	// Sleep for 30 seconds (Thanks Chery!)
	std::this_thread::sleep_for(std::chrono::seconds(30));

	// Load the stars save file
	loadVersusData();

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

static int ReturnTrue()
{
	return 1;
}

void GenerateDongleData(bool isTerminal)
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
	if (isTerminal)
	{
		memcpy(hasp_buffer + 0xD00, "272211990002", 12);
		hasp_buffer[0xD3E] = 0x63;
		hasp_buffer[0xD3F] = 0x9C;
	}
	else
	{
		memcpy(hasp_buffer + 0xD00, "272213990002", 12);
		hasp_buffer[0xD3E] = 0x65;
		hasp_buffer[0xD3F] = 0x9A;
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
	bindAddr.sin_addr.s_addr = inet_addr(ipaddr);
	bindAddr.sin_port = htons(50765);
	bind(sock, (sockaddr*)&bindAddr, sizeof(bindAddr));


	ip_mreq mreq;
	mreq.imr_multiaddr.s_addr = inet_addr("225.0.0.1");
	mreq.imr_interface.s_addr = inet_addr(ipaddr);

	setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));

	const uint8_t* byteSequences_Free[] = {
		terminalPackage1_Free,
		terminalPackage2_Free,
		terminalPackage3_Free,
		terminalPackage4_Free,
		terminalPackage5_Free,
		terminalPackage6_Free,
	};

	const size_t byteSizes_Free[] = {
		sizeof(terminalPackage1_Free),
		sizeof(terminalPackage2_Free),
		sizeof(terminalPackage3_Free),
		sizeof(terminalPackage4_Free),
		sizeof(terminalPackage5_Free),
		sizeof(terminalPackage6_Free),
	};

	const uint8_t* byteSequences_Event2P[] = {
		terminalPackage1_Event2P,
		terminalPackage2_Event2P,
		terminalPackage3_Event2P,
		terminalPackage4_Event2P,
		terminalPackage5_Event2P,
		terminalPackage6_Event2P,
	};

	const size_t byteSizes_Event2P[] = {
		sizeof(terminalPackage1_Event2P),
		sizeof(terminalPackage2_Event2P),
		sizeof(terminalPackage3_Event2P),
		sizeof(terminalPackage4_Event2P),
		sizeof(terminalPackage5_Event2P),
		sizeof(terminalPackage6_Event2P),
	};

	const uint8_t* byteSequences_Event4P[] = {
		terminalPackage1_Event4P,
		terminalPackage2_Event4P,
		terminalPackage3_Event4P,
		terminalPackage4_Event4P,
		terminalPackage5_Event4P,
		terminalPackage6_Event4P,
	};

	const size_t byteSizes_Event4P[] = {
		sizeof(terminalPackage1_Event4P),
		sizeof(terminalPackage2_Event4P),
		sizeof(terminalPackage3_Event4P),
		sizeof(terminalPackage4_Event4P),
		sizeof(terminalPackage5_Event4P),
		sizeof(terminalPackage6_Event4P),
	};

	const uint8_t* byteSequences_Coin[] = {
		terminalPackage1_Coin,
		terminalPackage2_Coin,
		terminalPackage3_Coin,
		terminalPackage4_Coin,
		terminalPackage5_Coin,
		terminalPackage6_Coin,
	};

	const size_t byteSizes_Coin[] = {
		sizeof(terminalPackage1_Coin),
		sizeof(terminalPackage2_Coin),
		sizeof(terminalPackage3_Coin),
		sizeof(terminalPackage4_Coin),
		sizeof(terminalPackage5_Coin),
		sizeof(terminalPackage6_Coin),
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

static DWORD WINAPI spamCustomName(LPVOID)
{
	while (true)
	{
		Sleep(50);
		void* value = (void*)(imageBase + 0x194C230);
		memcpy(value, customName, strlen(customName) + 1);
	}
}

extern int* ffbOffset;
extern int* ffbOffset2;
extern int* ffbOffset3;
extern int* ffbOffset4;

DWORD WINAPI Wmmt5FfbCollector(void* ctx)
{
	uintptr_t imageBase = (uintptr_t)GetModuleHandleA(0);
	while (true)
	{
		*ffbOffset = *(DWORD*)(imageBase + 0x196F188);
		*ffbOffset2 = *(DWORD*)(imageBase + 0x196F18c);
		*ffbOffset3 = *(DWORD*)(imageBase + 0x196F190);
		*ffbOffset4 = *(DWORD*)(imageBase + 0x196F194);
		Sleep(10);
	}
}

#pragma endregion

#pragma region main

static InitFunction Wmmt5Func([]()
{
#ifdef _DEBUG
	writeLog("Game: Wangan Midnight Maximum Tune 5");
	writeLog("Call to init function ...");
#endif

	// Custom Name Stuff

	// Get the custom name specified in the  config file
	std::string tempName = config["General"]["CustomName"];

	// If a custom name is set
	if (!tempName.empty())
	{
		// Zero out the custom name variable
		memset(customName, 0x0, 0xFF);

		// Copy the custom name to the custom name block
		strcpy(customName, tempName.c_str());
	}

	FILE* fileF = _wfopen(L"Fsetting.lua.gz", L"r");
	if (fileF == NULL)
	{
		FILE* settingsF = _wfopen(L"Fsetting.lua.gz", L"wb");
		fwrite(settingData, 1, sizeof(settingData), settingsF);
		fclose(settingsF);
	}
	else
	{
		fclose(fileF);
	}

	FILE* fileG = _wfopen(L"Gsetting.lua.gz", L"r");
	if (fileG == NULL)
	{
		FILE* settingsG = _wfopen(L"Gsetting.lua.gz", L"wb");
		fwrite(settingData, 1, sizeof(settingData), settingsG);
		fclose(settingsG);
	}
	else
	{
		fclose(fileG);
	}

	bool isTerminal = false;
	if (ToBool(config["General"]["TerminalMode"]))
	{
		isTerminal = true;
	}

	std::string networkip = config["General"]["NetworkAdapterIP"];
	if (!networkip.empty())
	{
		ipaddr = networkip.c_str();
	}

	hookPort = "COM3";
	imageBase = (uintptr_t)GetModuleHandleA(0);

	MH_Initialize();
	
	// Hook dongle funcs
	MH_CreateHookApi(L"hasp_windows_x64_109906.dll", "hasp_write", Hook_hasp_write, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_109906.dll", "hasp_read", Hook_hasp_read, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_109906.dll", "hasp_get_size", Hook_hasp_get_size, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_109906.dll", "hasp_decrypt", Hook_hasp_decrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_109906.dll", "hasp_encrypt", Hook_hasp_encrypt, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_109906.dll", "hasp_logout", Hook_hasp_logout, NULL);
	MH_CreateHookApi(L"hasp_windows_x64_109906.dll", "hasp_login", Hook_hasp_login, NULL);
	MH_CreateHookApi(L"WS2_32", "bind", Hook_bind, reinterpret_cast<LPVOID*>(&pbind));

	GenerateDongleData(isTerminal);

	// Patch some check
	// 0F 94 C0 84 C0 0F 94 C0 84 C0 75 05 45 32 E4 EB 03 41 B4 01
	// FOUND ON 21, 10
	// NOT WORKING 1
	// 0F 94 C0 84 C0 0F 94 C0 84 C0 75 05 45 32 ?? EB
	// FOUND ON 1
	//injector::WriteMemory<uint8_t>(imageBase + 0x6286EC, 0, true); 
	injector::WriteMemory<uint8_t>(hook::get_pattern("0F 94 C0 84 C0 0F 94 C0 84 C0 75 05 45 32 ? EB", 0x13), 0, true);

	// Patch some jnz
	// 83 C0 FD 83 F8 01 0F 87 B4 00 00 00 83 BF D0 06 00 00 3C 73 29 48 8D 8D 60 06 00 00
	// FOUND ON 21, 10
	// NOT FOUND: 1
	// 83 C0 FD 83 F8 01 0F 87 B4 00 00 00
	// FOUND ON 1
	//injector::MakeNOP(imageBase + 0x628AE0, 6);
	injector::MakeNOP(hook::get_pattern("83 C0 FD 83 F8 01 0F 87 B4 00 00 00", 6), 6);

	// Patch some shit
	// 83 FA 04 0F 8C 1E 01 00 00 4C 89 44 24 18 4C 89 4C 24 20
	// FOUND ON 21, 10, 1
	// NOT FOUND:
	//injector::WriteMemory<uint8_t>(imageBase + 0x7B9882, 0, true);
	injector::WriteMemory<uint8_t>(hook::get_pattern("83 FA 04 0F 8C 1E 01 00 00 4C 89 44 24 18 4C 89 4C 24 20", 2), 0, true);

	// Skip weird camera init that stucks entire pc on certain brands. TESTED ONLY ON 05!!!!
	if (ToBool(config["General"]["WhiteScreenFix"]))
	{
		injector::WriteMemory<DWORD>(hook::get_pattern("48 8B C4 55 57 41 54 41 55 41 56 48 8D 68 A1 48 81 EC 90 00 00 00 48 C7 45 D7 FE FF FF FF 48 89 58 08 48 89 70 18 45 33 F6 4C 89 75 DF 33 C0 48 89 45 E7", 0), 0x90C3C032, true);
	}

	// Patch some call
	// 45 33 C0 BA 65 09 00 00 48 8D 4D B0 E8 ?? ?? ?? ?? 48 8B 08
	// FOUND ON 21, 10, 1
	//injector::MakeNOP(imageBase + 0x7DADED, 5);
	injector::MakeNOP(hook::get_pattern("45 33 C0 BA 65 09 00 00 48 8D 4D B0 E8 ? ? ? ? 48 8B 08", 12), 5);
	{
		// 199AE18 TIME OFFSET RVA

		auto location = hook::get_pattern<char>("41 3B C7 74 0E 48 8D 8F B8 00 00 00 BA F6 01 00 00 EB 6E 48 8D 8F A0 00 00 00");
		// Patch some jnz
		// 41 3B C7 74 0E 48 8D 8F B8 00 00 00 BA F6 01 00 00 EB 6E 48 8D 8F A0 00 00 00
		// FOUND ON 21, 10, 1
		//injector::WriteMemory<uint8_t>(imageBase + 0x943F52, 0xEB, true);
		injector::WriteMemory<uint8_t>(location + 3, 0xEB, true);

		// Skip some jnz
		//injector::MakeNOP(imageBase + 0x943F71, 2);
		injector::MakeNOP(location + 0x22, 2);

		// Skip some jnz
		//injector::MakeNOP(imageBase + 0x943F82, 2);
		injector::MakeNOP(location + 0x33, 2);
	}

	// Skip DebugBreak on MFStartup fail
	// 48 83 EC 28 33 D2 B9 70 00 02 00 E8 ?? ?? ?? ?? 85 C0 79 06
	// FOUND on 21, 1
	{
		auto location = hook::get_pattern<char>("48 83 EC 28 33 D2 B9 70 00 02 00 E8 ? ? ? ? 85 C0 79 06");
		injector::WriteMemory<uint8_t>(location + 0x12, 0xEB, true);
	}

	// Terminal mode is on
	if (isTerminal)
	{
		// Patch some func to 1
		// 
		// FOUND ON 21, 10, 1
		// NOT FOUND:
		//safeJMP(imageBase + 0x7BE440, ReturnTrue);
		safeJMP(hook::get_pattern("0F B6 41 05 2C 30 3C 09 77 04 0F BE C0 C3 83 C8 FF C3"), ReturnTrue);

		// Patch some func to 1
		// 40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 28 48 8D ?? ?? ?? ?? 00 48 8D ?? ?? ?? ?? 00 41 B8 ?? ?? 00 00 FF 15 ?? ?? ?? ?? 4C 8B 1B 41 0F B6 43 78
		// FOUND ON 21, 10, 1
		//safeJMP(imageBase + 0x7CF8D0, ReturnTrue);
		safeJMP(hook::get_pattern("40 53 48 83 EC 20 48 83 39 00 48 8B D9 75 28 48 8D ? ? ? ? 00 48 8D ? ? ? ? 00 41 B8 ? ? 00 00 FF 15 ? ? ? ? 4C 8B 1B 41 0F B6 43 78"), ReturnTrue);
	}
	else // Terminal mode is off
	{
		// Disregard terminal scanner stuff.
		// 48 8B 18 48 3B D8 0F 84 88 00 00 00 39 7B 1C 74 60 80 7B 31 00 75 4F 48 8B 43 10 80 78 31 00
		// FOUND ON 21, 10, 1
		//injector::MakeNOP(imageBase + 0x91E1AE, 6);
		//injector::MakeNOP(imageBase + 0x91E1B7, 2);
		//injector::MakeNOP(imageBase + 0x91E1BD, 2);
		{
			auto location = hook::get_pattern<char>("48 8B 18 48 3B D8 0F 84 88 00 00 00 39 7B 1C 74 60 80 7B 31 00 75 4F 48 8B 43 10 80 78 31 00");
			injector::MakeNOP(location + 6, 6); // 6
			injector::MakeNOP(location + 0xF, 2); // 0xF
			injector::MakeNOP(location + 0x15, 2); // 0x15
		}
	}

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

	// Save story stuff (only 05)
	{
		// Skip erasing of temp card data
		injector::WriteMemory<uint8_t>(imageBase + 0x8DEBC3, 0xEB, true);

		safeJMP(imageBase + 0x5612F0, ReturnTrue);
		safeJMP(imageBase + 0x5753C0, ReturnTrue);
		safeJMP(imageBase + 0x57DF10, ReturnTrue);

		safeJMP(imageBase + 0x92DB20, ReturnTrue);
		safeJMP(imageBase + 0x579090, ReturnTrue);

		// Skip more
		safeJMP(imageBase + 0x54B0F0, ReturnTrue);
		safeJMP(imageBase + 0x909DB0, ReturnTrue);
		safeJMP(imageBase + 0x59FD90, ReturnTrue);
		safeJMP(imageBase + 0x5A0030, ReturnTrue);
		safeJMP(imageBase + 0x915370, ReturnTrue);
		safeJMP(imageBase + 0x5507A0, ReturnTrue);
		safeJMP(imageBase + 0x561290, ReturnTrue);

		// Check for vanilla mode
		bool vanillaMode = ToBool(config["General"]["Vanilla Mode (No Patches)"]);

		// Vanilla mode is set
		if (!vanillaMode)
		{
			// Enable load / save hooks
			
			// Load story and car data

			// Load game trigger
			safeJMP(imageBase + 0x5A0AE8, loadGame);

			// Save game data trigger
			injector::MakeNOP(imageBase + 0x308546, 0x12);
			injector::WriteMemory<WORD>(imageBase + 0x308546, 0xB848, true);
			injector::WriteMemory<uintptr_t>(imageBase + 0x308546 + 2, (uintptr_t)SaveGameData, true);
			injector::WriteMemory<DWORD>(imageBase + 0x308550, 0x3348D0FF, true);
			injector::WriteMemory<WORD>(imageBase + 0x308550 + 4, 0x90C0, true);

			// Prevents startup saving
			injector::WriteMemory<WORD>(imageBase + 0x556CE3, 0xB848, true);
			injector::WriteMemory<uintptr_t>(imageBase + 0x556CE3 + 2, (uintptr_t)SaveOk, true);
			injector::WriteMemory<DWORD>(imageBase + 0x556CED, 0x9090D0FF, true);

			// If we are not running as a terminal, and terminal emu is enabled
			if ((!isTerminal) && ToBool(config["General"]["TerminalEmulator"]))
			{
				// Create the terminal emulator thread
				CreateThread(0, 0, SpamMulticast, 0, 0, 0);
			}
		}

		// Start force feedback thread
		CreateThread(0, 0, Wmmt5FfbCollector, 0, 0, 0);
	}

	MH_EnableHook(MH_ALL_HOOKS);
	 
#ifdef _DEBUG
	writeLog("Init function done.");
#endif
}, GameID::WMMT5);
#endif
#pragma optimize("", on)
#pragma endregion