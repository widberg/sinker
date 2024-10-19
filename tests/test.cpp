#include <cstdio>
#include <sstream>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <sinker/sinker.hpp>

TEST_CASE("Script Empty Input", "[script]") {
    sinker::Context context;

    std::string input = "";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));

    std::stringstream output;
    context.dump(output);

    REQUIRE(output.str() == input);
}

TEST_CASE("Script FMTK Integration Test", "[script]") {
    sinker::Context context;

    std::string input =
        R"?(module fuel;
variant fuel, retail, "ac1b2077137b7c6299c344111857b032635fe3d4794bc5135dad7c35feeda856";
symbol fuel::pGlobalCommandState, "const void**";
address fuel::pGlobalCommandState, [retail], @10993792;
symbol fuel::CoreMainLoop, "void (__stdcall *)()";
tag fuel::CoreMainLoop, hook;
address fuel::CoreMainLoop, [retail], @6851568;
symbol fuel::RegisterCommand, "void (__usercall *)(LPCSTR name@<edi>, LPCVOID pThis, LPVOID callback)";
tag fuel::RegisterCommand, hook;
address fuel::RegisterCommand, [retail], @6923264;
symbol fuel::RunCommand, "bool (__stdcall *)(LPCVOID pState, LPCSTR cmd, DWORD depth)";
tag fuel::RunCommand, hook;
address fuel::RunCommand, [retail], @6923664;
symbol fuel::WinMain, "INT (WINAPI *)(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)";
tag fuel::WinMain, hook;
address fuel::WinMain, [retail], @8512320;
symbol fuel::ScriptManagerInit, "void (__fastcall *)(DWORD x, DWORD y, DWORD z)";
tag fuel::ScriptManagerInit, hook;
address fuel::ScriptManagerInit, [retail], @8506800;
symbol fuel::GetPlayerPosition, "bool (__usercall *)@<al>(float *playerPosVecOut@<edi>)";
address fuel::GetPlayerPosition, [retail], @4333408;
symbol fuel::securom, "int (__stdcall *)()";
tag fuel::securom, hook;
address fuel::securom, [retail], @8668096;
symbol fuel::securom_buffer, "std::uint8_t*";
address fuel::securom_buffer, [retail], @10767328;
symbol fuel::GetInputState, "LPCVOID (__stdcall *)(int a)";
address fuel::GetInputState, [retail], @5611200;
symbol fuel::GetKeyState, "KeyState *(__userpurge *)@<eax>(LPCVOID pState@<eax>, short key_code)";
address fuel::GetKeyState, [retail], @4299872;
module kernel32, "Kernel32.dll";
symbol kernel32::CreateFileW, "HANDLE (WINAPI *)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)";
tag kernel32::CreateFileW, hook;
address kernel32::CreateFileW, [*], !kernel32::CreateFileW;
symbol kernel32::OutputDebugStringA, "void (WINAPI *)(LPCSTR lpOutputString)";
tag kernel32::OutputDebugStringA, hook;
address kernel32::OutputDebugStringA, [*], !kernel32::OutputDebugStringA;
symbol kernel32::OutputDebugStringW, "void (WINAPI *)(LPCWSTR lpOutputString)";
tag kernel32::OutputDebugStringW, hook;
address kernel32::OutputDebugStringW, [*], !kernel32::OutputDebugStringW;
symbol kernel32::ReadFile, "BOOL (WINAPI *)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)";
tag kernel32::ReadFile, hook;
address kernel32::ReadFile, [*], !kernel32::ReadFile;
module user32, "User32.dll";
symbol user32::CreateWindowExW, "HWND (WINAPI *)(DWORD dwExStyle, LPCWSTR lpClassName, LPCWSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)";
address user32::CreateWindowExW, [*], !user32::CreateWindowExW;
symbol user32::CreateDialogParamA, "HWND (WINAPI *)(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam)";
tag user32::CreateDialogParamA, hook;
address user32::CreateDialogParamA, [*], !user32::CreateDialogParamA;
symbol user32::SendMessageA, "LRESULT (WINAPI *)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)";
tag user32::SendMessageA, hook;
address user32::SendMessageA, [*], !user32::SendMessageA;
module advapi32, "Advapi32.dll";
symbol advapi32::RegQueryValueExW, "LSTATUS (WINAPI *)(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)";
tag advapi32::RegQueryValueExW, hook;
address advapi32::RegQueryValueExW, [*], !advapi32::RegQueryValueExW;
module d3dx9_39, "d3dx9_39.dll";
symbol d3dx9_39::D3DXCompileShaderFromFileA, "HRESULT (WINAPI *)(LPCSTR pSrcFile, CONST D3DXMACRO* pDefines, LPD3DXINCLUDE pInclude, LPCSTR pFunctionName, LPCSTR pProfile, DWORD Flags, LPD3DXBUFFER* ppShader, LPD3DXBUFFER* ppErrorMsgs, LPD3DXCONSTANTTABLE* ppConstantTable)";
tag d3dx9_39::D3DXCompileShaderFromFileA, hook;
address d3dx9_39::D3DXCompileShaderFromFileA, [*], !d3dx9_39::D3DXCompileShaderFromFileA;
module xlive, "xlive.dll";
variant xlive, v3_5_95_0, "8ae328cc7e9f22a8ed1b63f7f0c4977e36bc6c7f7582f1b8e41f1fdf960d5796";
symbol xlive::ValidateMemory, "INT (WINAPI *)(DWORD, DWORD, DWORD)";
set xlive::ValidateMemory, required, false;
address xlive::ValidateMemory, [v3_5_95_0], @5191347;
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "fmtk.skr"));

    std::stringstream output;
    context.dump(output);
    REQUIRE(output.str() == input);
}

TEST_CASE("Script Pattern Match", "[script]") {
    sinker::Context context;

    std::string input = R"?(module fuel;
variant fuel, retail, "ac1b2077137b7c6299c344111857b032635fe3d4794bc5135dad7c35feeda856";
symbol fuel::pGlobalCommandState, "const void**";
address fuel::pGlobalCommandState, [retail], { DE AD BE EF };
address fuel::pGlobalCommandState, [retail], { ?? ?D &B? EF };
address fuel::pGlobalCommandState, [retail], [fuel::".text"]{ DE AD BE EF "test" : 00 0F F0 FF FF FF FF FF };
)?";

    std::string output = R"?(module fuel;
variant fuel, retail, "ac1b2077137b7c6299c344111857b032635fe3d4794bc5135dad7c35feeda856";
symbol fuel::pGlobalCommandState, "const void**";
address fuel::pGlobalCommandState, [retail], { DE AD BE EF : FF FF FF FF };
address fuel::pGlobalCommandState, [retail], { 00 0D &B0 EF : 00 0F F0 FF };
address fuel::pGlobalCommandState, [retail], [fuel::".text"]{ DE AD BE EF 74 65 73 74 : 00 0F F0 FF FF FF FF FF };
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));

    std::stringstream out;
    context.dump(out);
    REQUIRE(out.str() == output);
}

TEST_CASE("Script Empty Statements", "[script]") {
    sinker::Context context;

    std::string input = ";;;;;;;;;;;;;;;";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));
}

TEST_CASE("Runtime Pattern Match", "[runtime]") {
    std::uint8_t data[] = {0x74, 0x65, 0xDE, 0xAD, 0xBE, 0xEF, 0x73, 0x74};

    sinker::PatternMatchNeedle needle(
        {{0xDE, 0xFF}, {0xAD, 0xFF}, {0xBE, 0xFF}, {0xEF, 0xFF}});

    void *result = needle.search(data, data + sizeof(data));

    REQUIRE(result == data + 2);
}

TEST_CASE("Runtime Pattern Match Not Found", "[runtime]") {
    std::uint8_t data[] = {0x74, 0x65, 0xDE, 0xFF, 0xFF, 0xEF, 0x73, 0x74};

    sinker::PatternMatchNeedle needle(
        {{0xDE, 0xFF}, {0xAD, 0xF0}, {0xBE, 0x0F}, {0xEF, 0xFF}});

    void *result = needle.search(data, data + sizeof(data));

    REQUIRE(result == data + sizeof(data));
}

TEST_CASE("Runtime Pattern Match Mask", "[runtime]") {
    std::uint8_t data[] = {0x74, 0x65, 0xDE, 0xAF, 0xFE, 0xEF, 0x73, 0x74};

    sinker::PatternMatchNeedle needle(
        {{0xDE, 0xFF}, {0xAD, 0xF0}, {0xBE, 0x0F}, {0xEF, 0xFF}});

    void *result = needle.search(data, data + sizeof(data));

    REQUIRE(result == data + 2);
}

TEST_CASE("Runtime CheckDereference", "[runtime]") {
    sinker::Context context;

    std::string input = R"?(module fuel;
symbol fuel::pGlobalCommandState, "const void**";
address fuel::pGlobalCommandState, [*], ptr*0;
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));
    REQUIRE_FALSE(context.get_module("fuel")
                      ->get_symbol("pGlobalCommandState")
                      ->calculate_address<void const **>());
}

TEST_CASE("Runtime Pattern Match Integration", "[runtime]") {
    sinker::Context context;

    static char const *data = "Houston, we have a problem.";

    // Break up strings in pattern match so that it only matches the data string
    // above
    std::string input = R"?(module fuel;
symbol fuel::pGlobalCommandState, "const char *";
address fuel::pGlobalCommandState, [*], [fuel]{ "To be or not to be, " "that is the question." };
address fuel::pGlobalCommandState, [*], [fuel]{ "Houston, " &"we have a problem." };
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));
    REQUIRE(context.get_module("fuel")->concretize());
    auto result = context.get_module("fuel")
                      ->get_symbol("pGlobalCommandState")
                      ->calculate_address<char const *>();
    REQUIRE(result);
    REQUIRE((void *)result.value() == (void *)(data + 9));
}

TEST_CASE("Runtime Pattern Match Variant", "[runtime]") {
    sinker::Context context;

    static char const *data =
        "Darkness cannot drive out darkness; only light can do that. Hate "
        "cannot drive out hate; only love can do that.";

    std::string input = R"?(module fuel;
variant fuel, no, [fuel]{ "The darker the night, " "the brighter the stars." };
variant fuel, yes, [fuel]{ "Darkness cannot drive out darkness; only light can do that. " "Hate cannot drive out hate; only love can do that." };
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));
    REQUIRE(context.get_module("fuel")->concretize());
    REQUIRE(context.get_module("fuel")->get_real_variant() == "yes");
    REQUIRE(data); // Prevent data from being optimized out
}

TEST_CASE("Runtime Pattern Match Wide String", "[runtime]") {
    sinker::Context context;

    static char const *data_ascii = "A wilderness explorer is a friend to all, "
                                    "be a plant or fish or tiny mole!";
    static wchar_t const *data_wide = L"A wilderness explorer is a friend to "
                                      L"all, be a plant or fish or tiny mole!";

    std::string input = R"?(module fuel;
symbol fuel::ascii, "const char *";
address fuel::ascii, [*], [fuel]{ "A wilderness explorer is a friend to all, " &"be a plant or fish or tiny mole!" ascii };
symbol fuel::wide, "const wchar_t *";
address fuel::wide, [*], [fuel]{ "A wilderness explorer is a friend to all, " wide &"be a plant or fish or tiny mole!" wide };
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));
    REQUIRE(context.get_module("fuel")->concretize());
    auto result_ascii = context.get_module("fuel")
                            ->get_symbol("ascii")
                            ->calculate_address<char const *>();
    REQUIRE(result_ascii);
    REQUIRE((void *)result_ascii.value() == (void *)(data_ascii + 42));
    auto result_wide = context.get_module("fuel")
                           ->get_symbol("wide")
                           ->calculate_address<wchar_t const *>();
    REQUIRE(result_wide);
    REQUIRE((void *)result_wide.value() == (void *)(data_wide + 42));
}

TEST_CASE("Runtime Short Circuit Operators", "[runtime]") {
    sinker::Context context;

    std::string input = R"?(module fuel;
symbol fuel::ShortCircuitAndUnresolved, "void *";
address fuel::ShortCircuitAndUnresolved, [*], ptr*0 && 1;
symbol fuel::ShortCircuitAndResolved, "void *";
address fuel::ShortCircuitAndResolved, [*], 1 && 2;
symbol fuel::ShortCircuitOrUnresolved, "void *";
address fuel::ShortCircuitOrUnresolved, [*], ptr*0 || ptr*0;
symbol fuel::ShortCircuitOrResolved, "void *";
address fuel::ShortCircuitOrResolved, [*], ptr*0 || 1;
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));

    std::stringstream output;
    context.dump(output);
    REQUIRE(output.str() == input);

    REQUIRE(context.get_module("fuel")->concretize());
    auto result_au = context.get_module("fuel")
                         ->get_symbol("ShortCircuitAndUnresolved")
                         ->calculate_address<void *>();
    REQUIRE(!result_au);
    auto result_ar = context.get_module("fuel")
                         ->get_symbol("ShortCircuitAndResolved")
                         ->calculate_address<void *>();
    REQUIRE(result_ar);
    REQUIRE((void *)result_ar.value() == (void *)2);
    auto result_ou = context.get_module("fuel")
                         ->get_symbol("ShortCircuitOrUnresolved")
                         ->calculate_address<void *>();
    REQUIRE(!result_ou);
    auto result_or = context.get_module("fuel")
                         ->get_symbol("ShortCircuitOrResolved")
                         ->calculate_address<void *>();
    REQUIRE(result_or);
    REQUIRE((void *)result_or.value() == (void *)1);
}
