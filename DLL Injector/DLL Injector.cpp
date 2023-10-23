// DLL Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>

DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry)) {
            do {
                if (!wcscmp(procEntry.szExeFile, procName)) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
                    
            } while (Process32Next(hSnap, &procEntry));
        }
    }

    CloseHandle(hSnap);

    return procId;


}

int main()
{
    const char* d11Path = "YOUR_DLL_PATH";
    const wchar_t* procName = L"PROCESS_NAME.exe";
    DWORD procId = 0;

    while (!procId) {
        procId = GetProcId(procName);
		Sleep(30);
    }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE) {
        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (loc) {

            WriteProcessMemory(hProc, loc, d11Path, strlen(d11Path) + 1, 0);

            HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

            if (hThread)
                CloseHandle(hThread);

        }
    }

    if (hProc)
        CloseHandle(hProc);

    return 0;
}
