#include <sstream>
#include <string>

#include <catch2/catch_test_macros.hpp>
#include <sinker/sinker.hpp>

TEST_CASE("DSL Empty Input", "[dsl]") {
    sinker::Context context;

    std::string input = "";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));

    std::stringstream output;
    context.dump(output);

    REQUIRE(output.str() == input);
}

TEST_CASE("DSL FMTK Integration Test", "[dsl]") {
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

TEST_CASE("DSL Pattern Match", "[dsl]") {
    sinker::Context context;

    std::string input = R"?(module fuel;
variant fuel, retail, "ac1b2077137b7c6299c344111857b032635fe3d4794bc5135dad7c35feeda856";
symbol fuel::pGlobalCommandState, "const void**";
address fuel::pGlobalCommandState, [retail], { DE AD BE EF };
address fuel::pGlobalCommandState, [retail], { ?? ?D B? EF };
address fuel::pGlobalCommandState, [retail], { DE AD BE EF : 00 0F F0 FF };
)?";

    std::string output = R"?(module fuel;
variant fuel, retail, "ac1b2077137b7c6299c344111857b032635fe3d4794bc5135dad7c35feeda856";
symbol fuel::pGlobalCommandState, "const void**";
address fuel::pGlobalCommandState, [retail], { DE AD BE EF : FF FF FF FF };
address fuel::pGlobalCommandState, [retail], { 00 0D B0 EF : 00 0F F0 FF };
address fuel::pGlobalCommandState, [retail], { DE AD BE EF : 00 0F F0 FF };
)?";

    REQUIRE(context.interpret(input, sinker::Language::SINKER, "test.skr"));

    std::stringstream out;
    context.dump(out);

    REQUIRE(out.str() == output);
}
