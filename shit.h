#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <winscard.h>
BOOL Compare(PBYTE Data, LPCSTR Signature, LPCSTR Mask) {
    for (; *Mask; ++Signature, ++Mask, ++Data)
    {
        if (*Data != *(PBYTE)Signature && *Mask == 'x')
            return 0;
    }
    return 1;
}

PBYTE FindPattern(LPCSTR Signature, LPCSTR Mask)
{
    MODULEINFO mInfo{};
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(0), &mInfo, sizeof(mInfo));

    for (DWORD i = 0; i < mInfo.SizeOfImage; i++)
    {
        if (Compare((PBYTE)mInfo.lpBaseOfDll + i, Signature, Mask))
        {
            return (PBYTE)mInfo.lpBaseOfDll + i;
        }
    }

    return 0;
}
