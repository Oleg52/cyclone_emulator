#include <windows.h>
#include "logging.h"
#include "winmm_hook.h"
#include "hook_helper.h"
#include "crypto.h"

enum ReadRequestType
{
	DecodeMsid,
	EncodeFaid,
	GetCredits,
	Unknown
};

static const BYTE g_MsigDecodeTemplate[] = {0x1C,0x00,0x00,0x12,0x00,0x40,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x00,0x00};
static const BYTE g_FaidEncodeTemplate[] = {0x1C,0x00,0x00,0x12,0x00,0x00,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x00,0x00};
static const BYTE g_CreditsResponseTemplate[] = {0x1C,0x00,0x00,0x08,0x00,0x00,0x04,0x10,0x20,0x90,0x00,0x00};

static ReadRequestType g_ReadRequestType = Unknown;
static BYTE g_LastMsid[13];

typedef int(__cdecl* UsbBulk_t)(void*,int,BYTE*,int,int);
UsbBulk_t UsbBulkWriteOrigFunc = NULL;
UsbBulk_t UsbBulkReadOrigFunc = NULL;

int __cdecl UsbBulkWrite_Hook(void* dev, int ep, BYTE* bytes, int size, int timeout)
{
    g_ReadRequestType = Unknown;
    LogBufferToFile("UsbBulkWrite", bytes, size);

    if (size == 31 && bytes[0] == 0x1C && bytes[12] == 0x40)
    {
        if (msid_decode(bytes + 16, NULL, NULL, NULL, NULL))
        {
            memcpy(g_LastMsid, bytes + 16, sizeof(g_LastMsid));
            g_ReadRequestType = DecodeMsid;
            return size;
        }
    }

    if (size == 30 && bytes[0] == 0x1C && bytes[12] == 0x41)
    {
        g_ReadRequestType = EncodeFaid;
        return size;
    }

    int result = UsbBulkWriteOrigFunc(dev, ep, bytes, size, timeout);

    if (result >= 0 && size == 18 && bytes[0] == 0x1C && bytes[12] == 0x14)
    {
        g_ReadRequestType = GetCredits;
    }

    return result;
}

void CalculateChecksum(BYTE* bytes, int startIndex, int size)
{
    for (int i = startIndex; i < size - 1; i++)
    {
        bytes[size - 1] ^= bytes[i];
    }
}

int __cdecl UsbBulkRead_Hook(void* dev, int ep, BYTE* bytes, int size, int timeout)
{
    if (g_ReadRequestType == DecodeMsid || g_ReadRequestType == EncodeFaid)
    {
        BYTE msidValue[12];
        if (g_ReadRequestType == DecodeMsid)
        {
            msid_decode(g_LastMsid, NULL, NULL, NULL, msidValue);
            memcpy(bytes, g_MsigDecodeTemplate, sizeof(g_MsigDecodeTemplate));
        }
        else
        {
            msid_to_faid(g_LastMsid, msidValue);
            memcpy(bytes, g_FaidEncodeTemplate, sizeof(g_FaidEncodeTemplate));
        }

        memcpy(bytes + 7, msidValue, sizeof(msidValue));
        CalculateChecksum(bytes, 4, sizeof(g_MsigDecodeTemplate));

        LogBufferToFile("UsbBulkRead_Hook", bytes, sizeof(g_MsigDecodeTemplate));
        return sizeof(g_MsigDecodeTemplate);
    }

    int result = UsbBulkReadOrigFunc(dev, ep, bytes, size, timeout);

    if (g_ReadRequestType == GetCredits)
    {
        memcpy(bytes, g_CreditsResponseTemplate, sizeof(g_CreditsResponseTemplate));
        CalculateChecksum(bytes, 4, sizeof(g_CreditsResponseTemplate));
        LogBufferToFile("UsbBulkRead_Hook", bytes, sizeof(g_CreditsResponseTemplate));
        return sizeof(g_CreditsResponseTemplate);
    }

    if (result >= 0) LogBufferToFile("UsbBulkRead", bytes, result);
    else LogToFile("UsbBulkRead_Hook: Error %d", result);
    return result;
}

int WINAPI send_hook(void* s, const char *buf, int len, int flags)
{
    return 995;
}

typedef HMODULE(WINAPI* LoadLibraryA_t)(LPCSTR);
LoadLibraryA_t LoadLibraryAOrigFunc = NULL;

HMODULE WINAPI LoadLibraryA_Hook(LPCSTR lpLibFileName)
{
    HMODULE hModule = LoadLibraryAOrigFunc(lpLibFileName);
    if (lpLibFileName && hModule)
    {
        if (stricmp(lpLibFileName, "cyclonebox.dll") == 0)
        {
            EatHookFunction(hModule, "usb_bulk_read", (void**)&UsbBulkReadOrigFunc, (void*)UsbBulkRead_Hook, TRUE);
            EatHookFunction(hModule, "usb_bulk_write", (void**)&UsbBulkWriteOrigFunc, (void*)UsbBulkWrite_Hook, TRUE);
        }
    }

    return hModule;
}

void InstallHooks()
{
    IatHookFunction("kernel32.dll", "LoadLibraryA", (void**)&LoadLibraryAOrigFunc, (void*)LoadLibraryA_Hook, FALSE);
    IatHookFunction("cyclonebox.dll", "usb_bulk_read", (void**)&UsbBulkReadOrigFunc, (void*)UsbBulkRead_Hook, FALSE);
    IatHookFunction("cyclonebox.dll", "usb_bulk_write", (void**)&UsbBulkWriteOrigFunc, (void*)UsbBulkWrite_Hook, FALSE);

    // remove update check
    HMODULE winsock = LoadLibraryA("ws2_32.dll");
    if (winsock)
    {
        EatHookFunction(winsock, "send", NULL, (void*)send_hook, TRUE);
    }
}

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
		SetupWinmmFunctions();
        InstallHooks();
    }

    return TRUE;
}