// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <Hooking.Patterns.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

std::string_view Trim(std::string_view str)
{
	if (str.empty())
	{
		return "";
	}
	
	size_t last = str.find_last_not_of(" \t\n\r\v\f");
	return str.substr(0, (last + 1));
}

static void MyLogMessage(void* _this, int messageType, const char* format, va_list args)
{
	char buff[2048];
	vsnprintf_s(buff, 2048, format, args);
	spdlog::info(Trim(buff));
}

static void(*sfCallGameFromFlash_Callback_orig)(void* _this, void* pmovieView, const char* methodName, const void* argsPtr, uint32_t argCount);
static void sfCallGameFromFlash_Callback_detour(void* _this, void* pmovieView, const char* methodName, const void* argsPtr, uint32_t argCount)
{
	if (strcmp(methodName, "DEBUG_LOG") == 0)
	{
		struct
		{
			const void* args;

			void* get(uint32_t index) { return (char*)args + (ptrdiff_t)index * 0x18; }
			uint32_t typeof(uint32_t index) { return *(uint32_t*)((char*)get(index) + 0x8); }
			int asInt(uint32_t index) { return (int)*(double*)((char*)get(index) + 0x10); }
			const char* asStr(uint32_t index)
			{ 
				if (typeof(index) & 0x40) // is VTC_ManagedBit set
				{
					// get pStringManaged
					return **(const char***)((char*)get(index) + 0x10);
				}
				else
				{
					// get pString
					return *(const char**)((char*)get(index) + 0x10);
				}
			}
		} args = { argsPtr };

		// if arg 0 is number and arg 1 is string
		if ((args.typeof(0) & 0x8F) == 3 && (args.typeof(1) & 0x8F) == 4)
		{
			int scriptType = args.asInt(0);
			const char* str = args.asStr(1);

			static const char* scriptTypes[12] =
			{
				"GENERIC_TYPE",
				"SCRIPT_TYPE",
				"HUD_TYPE",
				"MINIMAP_TYPE",
				"WEB_TYPE",
				"CUTSCENE_TYPE",
				"PAUSE_TYPE",
				"STORE",
				"GAMESTREAM",
				"SF_BASE_CLASS_VIDEO_EDITOR",
				"SF_BASE_CLASS_MOUSE",
				"SF_BASE_CLASS_TEXT_INPUT",
			};

			if (scriptType >= 0 && scriptType < 12)
			{
				spdlog::info("[{}] {}", scriptTypes[scriptType], str);
			}
			else
			{
				spdlog::info(str);
			}
		}
	}
	else
	{
		sfCallGameFromFlash_Callback_orig(_this, pmovieView, methodName, argsPtr, argCount);
	}
}

static void Main()
{
	spdlog::set_default_logger(spdlog::basic_logger_mt("file_logger", "scaleform.log"));
	spdlog::set_pattern("[%Y-%m-%d %T.%e] %v");
	spdlog::flush_every(std::chrono::seconds(30));

	auto addr = hook::get_pattern<char>("89 78 10 44 89 78 08 48 8D 05 ? ? ? ?", 10);
	void** sfLogVTable = (void**)(addr + *(int*)addr + 4);
	sfLogVTable[1] = &MyLogMessage;

	addr = hook::get_pattern<char>("48 8D 0D ? ? ? ? C7 40 ? ? ? ? ? 48 89 08 89 68 08", 3);
	void** sfCallGameFromFlashVTable = (void**)(addr + *(int*)addr + 4);
	sfCallGameFromFlash_Callback_orig = (decltype(sfCallGameFromFlash_Callback_orig))sfCallGameFromFlashVTable[1];
	sfCallGameFromFlashVTable[1] = &sfCallGameFromFlash_Callback_detour;

	spdlog::info("=== Log initialized ===");
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		Main();
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		spdlog::shutdown();
	}

    return TRUE;
}

