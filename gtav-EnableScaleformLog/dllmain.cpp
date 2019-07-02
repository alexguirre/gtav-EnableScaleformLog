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

static void Main()
{
	spdlog::set_default_logger(spdlog::basic_logger_mt("file_logger", "scaleform.log"));
	spdlog::set_pattern("[%Y-%m-%d %T.%e] %v");
	spdlog::flush_every(std::chrono::seconds(30));

	auto addr = hook::get_pattern<char>("89 78 10 44 89 78 08 48 8D 05 ? ? ? ?", 10);
	void** sfLogVTable = (void**)(addr + *(int*)addr + 4);
	sfLogVTable[1] = &MyLogMessage;

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

