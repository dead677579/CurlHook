// dllmain.cpp : Defines the entry point for the DLL application.
#include <stdio.h>
#include <regex>
#include "MinHook.h"
#include "shit.h"

typedef INT(*Curlopt)(PVOID, INT, va_list);
Curlopt _CurlSetopt;

INT CurlHook(PVOID curl, INT option, va_list data) {
    switch (option) {
    case 64:
        *data = NULL;

    case 10004:
        *data = NULL;

    case 10002:
        break;    
    }

    return _CurlSetopt(curl, option, data);
}

INT Mainthread() {
    auto CurlSetoptAdress = FindPattern("\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x33\xED\x49\x8B\xF0", "xxxxxxxxxxxxxxxxxxxxxxxxx");
    if (!CurlSetoptAdress) {
        MessageBoxA(0, "Couldn't find adress!", "error", MB_ICONERROR);
        return FALSE;
    }
    MH_Initialize();
    MH_CreateHook((PVOID)CurlSetoptAdress, CurlHook, (PVOID*)&_CurlSetopt);
    if (MH_EnableHook((PVOID)CurlSetoptAdress) != MH_OK)
    {
        MessageBoxA(0, "Failed to hook CurlSetopt!", "error", MB_ICONERROR);
    }
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  dwreason,
                       LPVOID lpReserved
                     )
{
    switch (dwreason)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Mainthread, 0, 0, 0);
    case DLL_PROCESS_DETACH:
        FreeConsole();
        break;
    }
    return TRUE;
}

