#pragma once

#include <thread>

enum nesys_command : uint32_t
{
	CCOMMAND_ERROR = 0xFFFFFFFF,
	CCOMMAND_NONE = 0x0,
	LCOMMAND_CLIENT_START = 0x1,
	LCOMMAND_CONNECT_REQUEST = 0x2,
	LCOMMAND_DISCONNECT_REQUEST = 0x3,
	LCOMMAND_GAME_START_REQUEST = 0x4,
	LCOMMAND_GAME_END_REQUEST = 0x5,
	LCOMMAND_GAME_CONTINUE_REQUEST = 0x6,
	LCOMMAND_EVENT_DOWNLOAD_REQUEST = 0x7,
	LCOMMAND_EVENT_REQUEST_REQUEST = 0x8,
	LCOMMAND_CARD_SELECT_REQUEST = 0x9,
	LCOMMAND_CARD_INSERT_REQUEST = 0xA,
	LCOMMAND_CARD_UPDATE_REQUEST = 0xB,
	LCOMMAND_CARD_BUYS_ITEM_REQUEST = 0xC,
	LCOMMAND_CARD_TAKEOVER_REQUEST = 0xD,
	LCOMMAND_CARD_FORCE_TAKEOVER_REQUEST = 0xE,
	LCOMMAND_CARD_DECREASE_REQUEST = 0xF,
	LCOMMAND_CARD_REISSUE_TEST_REQUEST = 0x10,
	LCOMMAND_CARD_REISSUE_REQUEST = 0x11,
	LCOMMAND_CARD_PLAYED_LIST_REQUEST = 0x12,
	LCOMMAND_RANKING_DATA_REQUEST = 0x13,
	LCOMMAND_LOCALNW_INFO_REQUEST = 0x14,
	LCOMMAND_GLOBALADDR_REQUEST = 0x15,
	LCOMMAND_ECHO_REQUEST = 0x16,
	LCOMMAND_ADAPTER_INFO_REQUEST = 0x17,
	LCOMMAND_SERVICE_VERSION_REQUEST = 0x18,
	LCOMMAND_DHCP_RENEW_REQUEST = 0x19,
	LCOMMAND_HTTPACCESS_GET_REQUEST = 0x1A,
	LCOMMAND_HTTPACCESS_POST_REQUEST = 0x1B,
	LCOMMAND_UPLOAD_CONFIG_REQUEST = 0x1C,
	LCOMMAND_INCOME_START_REQUEST = 0x1D,
	LCOMMAND_INCOME_END_REQUEST = 0x1E,
	LCOMMAND_INCOME_CONTINUE_REQUEST = 0x1F,
	LCOMMAND_SET_INCOME_MODE_REQUEST = 0x20,
	LCOMMAND_DESTROY_MY_SERVICE = 0x21,
	LCOMMAND_INCOME_POINT_REQUEST = 0x22,
	LCOMMAND_GAMESTATUS_RESET_REQUEST = 0x23,
	LCOMMAND_ROW_EVENTDATA_LIST_REQUEST = 0x24,
	LCOMMAND_SHOPPING_REQUEST = 0x25,
	LCOMMAND_HTTPSACCESS_GET_REQUEST = 0x26,
	LCOMMAND_HTTPSACCESS_POST_REQUEST = 0x27,
	LCOMMAND_FREE_TICKET_REQUEST = 0x28,
	LCOMMAND_GAME_FREE_START_REQUEST = 0x29,
	LCOMMAND_GAME_FREE_END_REQUEST = 0x2A,
	LCOMMAND_INCOME_FREE_START_REQUEST = 0x2B,
	LCOMMAND_INCOME_FREE_END_REQUEST = 0x2C,
	LCOMMAND_CLIENT_END = 0xFF,
	SCOMMAND_NW_ERROR = 0x101,
	SCOMMAND_CERT_ERROR = 0x102,
	SCOMMAND_NWRECOVER_NOTICE = 0x103,
	SCOMMAND_SOON_MAINTENANCE_NOTICE = 0x104,
	SCOMMAND_LINKUP_NOTICE = 0x105,
	SCOMMAND_LINKLOCAL_MODE_NOTICE = 0x106,
	SCOMMAND_CERT_INIT_NOTICE = 0x107,
	SCOMMAND_CERT_REGULAR_NOTICE = 0x108,
	SCOMMAND_EFFECTIVE_EVENT_NOTICE = 0x109,
	SCOMMAND_INEFFECTIVE_EVENT_NOTICE = 0x10A,
	SCOMMAND_DHCP_RENEW_START = 0x10B,
	SCOMMAND_DHCP_COMPLETE_NOTICE = 0x10C,
	SCOMMAND_CLIENT_START_REPLY = 0x10D,
	SCOMMAND_CONNECT_REPLY = 0x10E,
	SCOMMAND_DISCONNECT_REPLY = 0x10F,
	SCOMMAND_GAME_STATUS_REPLY = 0x110,
	SCOMMAND_CARD_SELECT_REPLY = 0x111,
	SCOMMAND_CARD_INSERT_REPLY = 0x112,
	SCOMMAND_CARD_UPDATE_REPLY = 0x113,
	SCOMMAND_CARD_BUYS_ITEM_REPLY = 0x114,
	SCOMMAND_CARD_TAKEOVER_REPLY = 0x115,
	SCOMMAND_CARD_DECREASE_REPLY = 0x116,
	SCOMMAND_CARD_REISSUE_TEST_REPLY = 0x117,
	SCOMMAND_CARD_REISSUE_REPLY = 0x118,
	SCOMMAND_CARD_PLAYED_LIST_REPLY = 0x119,
	SCOMMAND_RANKING_DATA_REPLY = 0x11A,
	SCOMMAND_LOCALNW_INFO_REPLY = 0x11B,
	SCOMMAND_LOCALNW_INFO_NOTICE = 0x11C,
	SCOMMAND_GLOBALADDR_REPLY = 0x11D,
	SCOMMAND_ECHO_REPLY = 0x11E,
	SCOMMAND_ADAPTER_INFO_REPLY = 0x11F,
	SCOMMAND_SERVICE_VERSION_REPLY = 0x120,
	SCOMMAND_HTTPACCESS_START = 0x121,
	SCOMMAND_HTTPACCESS_REPLY = 0x122,
	SCOMMAND_UPLOAD_CONFIG_REPLY = 0x123,
	SCOMMAND_INCOME_STATUS_REPLY = 0x124,
	SCOMMAND_SET_INCOME_MODE_REPLY = 0x125,
	SCOMMAND_DESTROY_MY_SERVICE = 0x126,
	SCOMMAND_GAMESTATUS_RESET_REPLY = 0x127,
	SCOMMAND_ROW_EVENTDATA_LIST_REPLY = 0x128,
	SCOMMAND_SHOPPING_REPLY = 0x129,
	SCOMMAND_FREE_TICKET_REPLY = 0x130,
	SCOMMAND_CLIENT_END_REPLY = 0x1FF,
};

struct NesysCommandHeader
{
	nesys_command command;
	uint32_t length;
	uint8_t data[];
};

class NesysEmu
{
public:
	NesysEmu();

	~NesysEmu();

	void Initialize();

	void Shutdown();

private:
	void ProcessPipe(HANDLE hPipe);

	void ProcessRequest(const uint8_t* requestBuffer, size_t length);

	void ProcessRequestInternal(const NesysCommandHeader* header);

	template<typename T>
	void SendResponse(nesys_command command, T data)
	{
		SendResponse(command, data, sizeof(*data));
	}

	template<>
	void SendResponse<nullptr_t>(nesys_command command, nullptr_t data)
	{
		SendResponse(command, nullptr, 0);
	}

	void SendResponse(nesys_command command, const void* data, size_t dataSize);

private:
	bool m_initialized;

	std::map<nesys_command, std::function<void(const uint8_t*, size_t)>> m_commandHandlers;
};

void init_NesysEmu();