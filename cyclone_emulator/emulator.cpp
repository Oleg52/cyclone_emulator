#define _WIN32_WINNT 0x0400

#include <windows.h>
#include "logging.h"
#include "winmm_hook.h"
#include "hook_helper.h"
#include "nokia_crypto.h"
#include "blackberry_crypto.h"

enum ReadRequestType
{
	DecodeMsid,
	EncodeFaid,
	GetCredits,
	GetMeps,
	GetBBXGoldCounter,
	CalcMep,
	GetLumiaActivation,
	Unknown
};

static const BYTE g_MsigDecodeTemplate[] = {0x1C,0x00,0x00,0x12,0x00,0x40,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x00,0x00};
static const BYTE g_FaidEncodeTemplate[] = {0x1C,0x00,0x00,0x12,0x00,0x00,0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x00,0x00};
static const BYTE g_CreditsResponseTemplate[] = {0x1C,0x00,0x00,0x08,0x00,0x00,0x04,0x10,0x20,0x90,0x00,0x00};
static const BYTE g_BBXGoldCounterResponse[] = {0x1C,0x00,0x00,0x04,0x00,0x00,0x00,0x64};
static const BYTE g_LumiaActivationResponse[] = {0x1C,0x00,0x00,0x10,0x2F,0x83,0xA7,0xF0,0x54,0x11,0x7F,0xC2,0xBB,0x78,0x90,0x9E,0xD9,0xFC,0xCD,0xBB};

static ReadRequestType g_ReadRequestType = Unknown;
static BOOL g_EnableCounterEmulation = FALSE;
static BYTE g_LastMsid[13];

static BYTE g_LastBBImei[16];
static char g_LastMepName[14];

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
    if (size == 5 && bytes[0] == 0x1C && *(WORD*)(bytes + 3) == 0xC201)
    {
        g_ReadRequestType = GetMeps;
        return size;
    }
    if (size == 6 && bytes[0] == 0x1C && *(DWORD*)(bytes + 2) == 0x10C30200 && g_EnableCounterEmulation)
    {
        g_EnableCounterEmulation = FALSE;
        g_ReadRequestType = GetBBXGoldCounter;
        return size;
    }
    if (size == 8 && bytes[0] == 0x1C && *(DWORD*)(bytes + 4) == 0x415352CB)
    {
        g_ReadRequestType = GetLumiaActivation;
        return size;
    }
    if (size == 35 && bytes[0] == 0x1C && *(WORD*)(bytes + 3) == 0xBB1F)
    {
        g_ReadRequestType = CalcMep;
        memcpy(g_LastBBImei, bytes + 5, sizeof(g_LastBBImei));
        memcpy(g_LastMepName, bytes + 21, sizeof(g_LastMepName));
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
    if (g_ReadRequestType == GetMeps)
    {
        bytes[0] = 0x1C;
        bytes[1] = 0x00;
        int size = FillMepsBuffer(bytes + 4);
        bytes[2] = (BYTE)(size >> 8);
        bytes[3] = (BYTE)size;
        g_EnableCounterEmulation = TRUE;
        LogBufferToFile("UsbBulkRead_Hook", bytes, size);
        return size;
    }
    if (g_ReadRequestType == GetBBXGoldCounter)
    {
        memcpy(bytes, g_BBXGoldCounterResponse, sizeof(g_BBXGoldCounterResponse));
        LogBufferToFile("UsbBulkRead_Hook", bytes, sizeof(g_BBXGoldCounterResponse));
        return sizeof(g_BBXGoldCounterResponse);
    }
    if (g_ReadRequestType == GetLumiaActivation)
    {
        memcpy(bytes, g_LumiaActivationResponse, sizeof(g_LumiaActivationResponse));
        LogBufferToFile("UsbBulkRead_Hook", bytes, sizeof(g_LumiaActivationResponse));
        return sizeof(g_LumiaActivationResponse);
    }
    if (g_ReadRequestType == CalcMep)
    {
        bytes[0] = 0x1C; bytes[1] = 0x00; bytes[2] = 0x00; bytes[3] = 0x10;
        BYTE code[20];
        ZeroMemory(code, sizeof(code));
        g_LastBBImei[15]--;
        if (!CalculateMep(g_LastMepName, g_LastBBImei, code))
        {
            return -1;
        }

        int offset = 0;
        for (int i = 0; i < 16; i++)
        {
            offset += sprintf((char*)(bytes + 4 + offset), "%d", code[i]);
        }

        g_EnableCounterEmulation = TRUE;
        LogBufferToFile("UsbBulkRead_Hook", bytes, 20);
        return 20;
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