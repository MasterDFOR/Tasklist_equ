#include <Windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <Wtsapi32.h>
#include <cstddef>
#pragma comment(lib, "Wtsapi32.lib")

int main()
{
    HANDLE hToken;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    HANDLE hprocessSnap;
    std::cout << "MemoryUsage\t" << "Session#\t" << "UserName\t" << "ProcessName\t" << "PID" << std::endl;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    hprocessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(hprocessSnap, &pe32))
    {
        do
        {
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess)
            {
                hToken = nullptr;
                // Print the process memory usage
                PROCESS_MEMORY_COUNTERS_EX pmc;
                if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))!=0)
                {
                    std::cout << pmc.WorkingSetSize / 1024 << "K";
                }
                // print session ID
                DWORD sessionId;
                if (ProcessIdToSessionId(pe32.th32ProcessID,&sessionId))
                {
                    std::wcout << "\t" << sessionId;
                }
//                else{
//
//                    std::cout << '0' << "\t";
//                }


                if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
                {
                    DWORD tokenInfoLength = 0;
                    GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoLength);
                    TOKEN_USER* tokenUser = (TOKEN_USER*)new char[tokenInfoLength];
                    if (GetTokenInformation(hToken, TokenUser, tokenUser, tokenInfoLength, &tokenInfoLength))
                    {
                        char lpName[MAX_PATH];
                        char lpDomain[MAX_PATH];
                        DWORD nameLen = MAX_PATH;
                        DWORD domainLen = MAX_PATH;
                        SID_NAME_USE sidType;
                        if (LookupAccountSid(nullptr, tokenUser->User.Sid, lpName, &nameLen, lpDomain, &domainLen, &sidType))
                        {

                            std::cout << "\t" << lpDomain << "\\" << lpName;
                        }
                    }
                    CloseHandle(hToken);
                    delete[] tokenUser;
                }
                CloseHandle(hProcess);
            }

            std::cout << "\t" << pe32.szExeFile << "\t" << pe32.th32ProcessID << std::endl;
        } while (Process32Next(hprocessSnap, &pe32));
    }
    CloseHandle(hprocessSnap);
    return 0;
}
