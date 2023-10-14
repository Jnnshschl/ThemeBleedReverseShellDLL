#pragma once
/*
# RTFN (Runtime-Function stuff)

Use this to hide imports, reduce executeable size and make the life of a reverse engineer harder.

Win10 x86 and x64, should be case-insensitive for dll names and case-sensitive for procadresses.

Every string will be hashed using a compile-time FNV1A hash function so it doesn't leave any
of them in the executeable. This wont work if you set RTFN_AUTOLOAD_DLL to 1 as LoadLibraryW
needs the dll name.

If you dont want any stl dependecies, make sure to set RTFN_WITH_CACHE to 0, but keep in mind
that only RTFN_GET_ADDR and RTFN_GET_ADDR_T will be available.

## Examples:

### [EXISTING FUNCTION] GetCurrentProcess

Use this method to call functions that are declared in a header, this way you dont need to declare a typedef.

This example uses the GetCurrentProcess function from "windows.h".

#### With Caching

// call this once at the beginning of your program
RTFN_LOAD(L"kernel32.dll", GetCurrentProcess);

void* process = RTFN_CALL(GetCurrentProcess)();

#### Without Caching

void* process = RTFN_GET_ADDR(L"kernel32.dll", GetCurrentProcess)();

### [TYPEDEF FUNCTION] NtAllocateVirtualMemory

Use this method to call functions that are not declared in headers like the ones from ntdll.dll.

Create a typedef named EXACTLY the same as the function you want to call:

typedef unsigned long(__stdcall* NtAllocateVirtualMemory)(void* process, void** base, unsigned long* zero, size_t* size, unsigned long type, unsigned long protect);

#### With Caching

// call this once at the beginning of your program
RTFN_LOAD(L"ntdll.dll", NtAllocateVirtualMemory);

void* alloc = nullptr;
size_t size = 13374711;
RTFN_CALL_T(NtAllocateVirtualMemory)(reinterpret_cast<void*>(-1), &alloc, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

#### Without Caching

void* alloc = nullptr;
size_t size = 13374711;
RTFN_GET_ADDR_T(L"ntdll.dll", NtAllocateVirtualMemory)(reinterpret_cast<void*>(-1), &alloc, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

*/

// Enable module and procaddress caching, requires stl map.
// If disabled, you cannot use RTFN_LOAD and RTFN_CALL,
// you need to use RTFN_GET_ADDR.
#define RTFN_WITH_CACHE 0

// Enable this to auto-load missing dlls using LoadLibraryW
// Attention! This creates a string with the dll name in 
// your executeable, make sure you want this to happen.
#define RTFN_AUTOLOAD_DLL 0

// needed for the dos and pe header
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <intrin.h>
#ifdef _WIN64
#pragma intrinsic(__readgsqword)
#else
#pragma intrinsic(__readfsdword)
#endif

#include <type_traits>

#if RTFN_WITH_CACHE == 1
#include <map>
#endif

#include "FNV1A.hpp"

#define RTFN_CAST(fn, exp) reinterpret_cast<fn>(exp)

#define _RTFN_GET_ADDR(mod, fn) RTFN::RtFnGetProcAddress(CX_IFnv1a(mod), CX_Fnv1a(#fn))
#define RTFN_GET_ADDR(mod, fn) RTFN_CAST(decltype(&fn), _RTFN_GET_ADDR(mod, fn))
#define RTFN_GET_ADDR_T(mod, fn) RTFN_CAST(fn, _RTFN_GET_ADDR(mod, fn))

#if RTFN_WITH_CACHE == 1
#if RTFN_AUTOLOAD_DLL == 1
#define RTFN_LOAD(mod, fn) RTFN::RtFnProcAddressCached(mod, CX_Fnv1a(#fn))
#else
#define RTFN_LOAD(mod, fn) RTFN::RtFnProcAddressCached(CX_IFnv1a(mod), CX_Fnv1a(#fn))
#endif

#define _RTFN_CALL(fn) RTFN::RtFnGet(CX_Fnv1a(L#fn))
#define RTFN_CALL(fn) RTFN_CAST(decltype(&fn), _RTFN_CALL(fn))
#define RTFN_CALL_T(fn) RTFN_CAST(fn, _RTFN_CALL(fn))

#define RTFN_GET(fn) RTFN_CAST(decltype(&fn), RTFN::RtFnGet(CX_Fnv1a(L#fn)))
#define RTFN_INIT(mod, fn) if (!RTFN_LOAD(mod, fn)) { return false; }
#endif

namespace RTFN
{
    struct LIST_ENTRY
    {
        struct LIST_ENTRY* Flink;
        struct LIST_ENTRY* Blink;
    };

    struct LDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        void* DllBase;
        void* EntryPoint;
        size_t SizeOfImage;
        unsigned short FullDllNameLength;
        unsigned short FullDllNameMaximumLength;
        wchar_t* FullDllNameBuffer;
        unsigned short BaseDllNameLength;
        unsigned short BaseDllNameMaximumLength;
        wchar_t* BaseDllNameBuffer;
        unsigned long Flags;
        unsigned short LoadCount;
        unsigned short TlsIndex;
        union
        {
            LIST_ENTRY HashLinks;
            struct
            {
                void* SectionPointer;
                unsigned long CheckSum;
            };
        };
        union
        {
            unsigned long TimeDateStamp;
            void* LoadedImports;
        };
        void* EntryPointActivationContext;
        void* PatchInformation;
        LIST_ENTRY ForwarderLinks;
        LIST_ENTRY ServiceTagLinks;
        LIST_ENTRY StaticLinks;
    };

#if RTFN_WITH_CACHE == 1
    static std::map<FNV1A::fnvhash, void*> RtFnCache;
#endif

    /// <summary>
    /// Returns a pointer to the current PEB.
    /// </summary>
    /// <returns>PEB Pointer</returns>
    __forceinline intptr_t GetPeb() noexcept
    {
#ifdef _WIN64
        return __readgsqword(0x60);
#else
        return __readfsdword(0x30);
#endif
    }

    /// <summary>
    /// Returns a pointer to the current PEB_LDR_DATA.
    /// </summary>
    /// <returns>PEB_LDR_DATA Pointer</returns>
    __forceinline intptr_t GetPebLdrData() noexcept
    {
#ifdef _WIN64
        return *reinterpret_cast<intptr_t*>(GetPeb() + 0x18);
#else
        return *reinterpret_cast<intptr_t*>(GetPeb() + 0x0C);
#endif
    }

    /// <summary>
    /// Get a modules handle.
    /// </summary>
    /// <param name="modHash">FNV1A hash of the modules name, case-insensitive</param>
    /// <param name="moduleSize">Returns the modules size</param>
    /// <returns>Handle to the module or nullptr</returns>
    __forceinline void* ModuleHandle(FNV1A::fnvhash modHash, unsigned int* moduleSize = nullptr) noexcept
    {
#ifdef _WIN64
        auto ldrData = *reinterpret_cast<LDR_DATA_TABLE_ENTRY**>(GetPebLdrData() + 0x10);
#else
        auto ldrData = *reinterpret_cast<LDR_DATA_TABLE_ENTRY**>(GetPebLdrData() + 0x0C);
#endif
        const auto firstLdrData = ldrData;
        const auto charTypeSize = sizeof(std::remove_pointer_t<decltype(ldrData->BaseDllNameBuffer)>);

        do
        {
            if (FNV1A::IHashFixed(ldrData->BaseDllNameBuffer, ldrData->BaseDllNameLength / charTypeSize) == modHash)
            {
                if (moduleSize) { *moduleSize = ldrData->SizeOfImage; }
                return ldrData->DllBase;
            }
        } while (firstLdrData != (ldrData = reinterpret_cast<decltype(ldrData)>(ldrData->InLoadOrderLinks.Flink)));

        return nullptr;
    }

    /// <summary>
    /// Get the address of an exported function.
    /// </summary>
    /// <param name="mod">Modules base address</param>
    /// <param name="fnHash">FNV1A hash of the exports name, case-sensitive</param>
    /// <returns>Functions address or nullptr</returns>
    __forceinline void* ProcAddress(void* mod, FNV1A::fnvhash fnHash)
    {
        if (const auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(mod))
        {
            if (dosHeader->e_magic == 0x5A4D)
            {
                const auto base = reinterpret_cast<char*>(mod);
                const auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);

                if (ntHeaders->Signature == 0x4550)
                {
                    const auto exportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
                    const auto addressesOfNames = reinterpret_cast<unsigned long*>(base + exportDirectory->AddressOfNames);
                    const auto addressesOfOrdinals = reinterpret_cast<unsigned short*>(base + exportDirectory->AddressOfNameOrdinals);
                    const auto addressesOfFunctions = reinterpret_cast<unsigned long*>(base + exportDirectory->AddressOfFunctions);

                    for (decltype(exportDirectory->NumberOfNames) i = 0; i < exportDirectory->NumberOfNames; ++i)
                    {
                        if (FNV1A::Hash(base + addressesOfNames[i]) == fnHash)
                        {
                            return base + addressesOfFunctions[addressesOfOrdinals[i]];
                        }
                    }
                }
            }
        }

        return nullptr;
    }

    /// <summary>
    /// Wrapper to get the export of a module with one call.
    /// </summary>
    /// <param name="modName">FNV1A hash of the modules name, case-insensitive</param>
    /// <param name="name">FNV1A hash of the exports name, case-sensitive</param>
    /// <returns>Functions address or nullptr</returns>
    __forceinline void* RtFnGetProcAddress(FNV1A::fnvhash modName, FNV1A::fnvhash name) noexcept
    {
        return ProcAddress(ModuleHandle(modName), name);
    }

    /// <summary>
    /// Wrapper for the LoadLibraryA function.
    /// </summary>
    /// <param name="modName">Dll to load</param>
    /// <returns>Dll base or nullptr</returns>
    __forceinline void* RtFnLoadLibraryA(const char* modName) noexcept
    {
        if (auto loadLibrary = RtFnGetProcAddress(CX_Fnv1a(L"kernel32.dll"), CX_Fnv1a(L"LoadLibraryA")))
        {
            typedef void* (__stdcall* tLoadLibraryA)(const char*);
            const auto lla = reinterpret_cast<tLoadLibraryA>(loadLibrary)(modName);

#if RTFN_WITH_CACHE == 1
            RtFnCache[FNV1A::IHash(modName)] = lla;
#endif
            return lla;
        }

        return nullptr;
    }

    /// <summary>
    /// Wrapper for the LoadLibraryW function.
    /// </summary>
    /// <param name="modName">Dll to load</param>
    /// <returns>Dll base or nullptr</returns>
    __forceinline void* RtFnLoadLibraryW(const wchar_t* modName) noexcept
    {
        if (auto loadLibrary = RtFnGetProcAddress(CX_Fnv1a(L"kernel32.dll"), CX_Fnv1a(L"LoadLibraryW")))
        {
            typedef void* (__stdcall* tLoadLibraryW)(const wchar_t*);
            const auto llw = reinterpret_cast<tLoadLibraryW>(loadLibrary)(modName);

#if RTFN_WITH_CACHE == 1
            RtFnCache[FNV1A::IHash(modName)] = llw;
#endif
            return llw;
        }

        return nullptr;
    }

    /// <summary>
    /// Get a modules base address and cache it.
    /// </summary>
    /// <param name="modName">Module name</param>
    /// <returns>Module base address</returns>
    __forceinline void* RtFnModuleHandleCached(const wchar_t* modName) noexcept
    {
        const auto modHash = FNV1A::IHash(modName);

#if RTFN_WITH_CACHE == 1
        if (!RtFnCache.contains(modHash))
        {
            if (!(RtFnCache[modHash] = ModuleHandle(modHash)))
            {
                RtFnCache[modHash] = RtFnLoadLibraryW(modName);
            }
        }

        return RtFnCache[modHash];
#else
        if (auto mod = ModuleHandle(modHash))
        {
            return mod;
        }

        return RtFnLoadLibraryW(modName);
#endif
    }

    /// <summary>
    /// Get a procaddress cached.
    /// </summary>
    /// <param name="modName">Module name</param>
    /// <param name="name">Proc name</param>
    /// <returns>Procaddress</returns>
    __forceinline void* RtFnProcAddressCached(const wchar_t* modName, FNV1A::fnvhash name) noexcept
    {
#if RTFN_WITH_CACHE == 1
        return !RtFnCache.contains(name) ? RtFnCache[name] = ProcAddress(RtFnModuleHandleCached(modName), name) : RtFnCache[name];
#else
        return ProcAddress(RtFnModuleHandleCached(modName), name);
#endif
    }

    /// <summary>
    /// Get a modules base address and cache it.
    /// </summary>
    /// <param name="modHash">Module name</param>
    /// <returns>Modules base address</returns>
    __forceinline void* RtFnModuleHandleCached(FNV1A::fnvhash modHash) noexcept
    {
#if RTFN_WITH_CACHE == 1
        if (!RtFnCache.contains(modHash))
        {
            RtFnCache[modHash] = ModuleHandle(modHash);
        }

        return RtFnCache[modHash];
#else
        return ModuleHandle(modHash);
#endif
    }

    /// <summary>
    /// Load a procaddress into the RTFN cache.
    /// </summary>
    /// <param name="modHash">Module name</param>
    /// <param name="name">Proc name</param>
    /// <returns>Procaddress</returns>
    __forceinline void* RtFnProcAddressCached(FNV1A::fnvhash modHash, FNV1A::fnvhash name) noexcept
    {
#if RTFN_WITH_CACHE == 1
        return !RtFnCache.contains(name) ? RtFnCache[name] = ProcAddress(RtFnModuleHandleCached(modHash), name) : RtFnCache[name];
#else
        return ProcAddress(RtFnModuleHandleCached(modHash), name);
#endif
    }

#if RTFN_WITH_CACHE == 1
    /// <summary>
    /// Get an entry from the RTFN cache.
    /// </summary>
    /// <param name="hash">FNV1A hash</param>
    /// <returns>Cache entry or nullptr</returns>
    __forceinline void* RtFnGet(FNV1A::fnvhash hash) noexcept
    {
        return RtFnCache.contains(hash) ? RtFnCache[hash] : nullptr;
    }
#endif

    /// <summary>
    /// Check wheter a function is hooked or not.
    /// 
    /// TODO: implement much more detection mechanisms.
    /// </summary>
    /// <param name="void*">Function</param>
    /// <returns>true if hooked false if not</returns>
    __forceinline bool IsFunctionHooked(void* function) noexcept
    {
        if (function)
        {
            const auto proc = reinterpret_cast<char*>(function);

            // TODO: make this more realiable
            if (*proc == 0xE9)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Check wheter a function is hooked or not.
    /// </summary>
    /// <param name="mod">Module name</param>
    /// <param name="name">Proc name</param>
    /// <returns>true if hooked false if not</returns>
    __forceinline bool IsFunctionHooked(FNV1A::fnvhash mod, FNV1A::fnvhash name) noexcept
    {
        if (auto proc = RtFnGetProcAddress(mod, name))
        {
            return IsFunctionHooked(proc);
        }

        return false;
    }

    /// <summary>
    /// Search a memory pattern. Placeholder is the '?' char.
    /// </summary>
    /// <param name="pattern">Pattern to search as char array</param>
    /// <param name="patternSize">Size of the pattern array</param>
    /// <param name="memory">Start of the search area</param>
    /// <param name="memorySize">Size of the search are</param>
    /// <returns>Address if found, 0 if not</returns>
    __forceinline intptr_t SearchPattern(const unsigned char* pattern, const size_t patternSize, const void* memory, const size_t memorySize) noexcept
    {
        size_t patternPosition = 0;
        intptr_t possibleAddress = 0;
        const auto c = reinterpret_cast<const unsigned char*>(memory);

        for (size_t i = 0; i < memorySize; ++i)
        {
            if (c[i] == pattern[patternPosition] || pattern[patternPosition] == '?')
            {
                if (patternPosition == 0)
                {
                    possibleAddress = i;
                }
                else if (patternPosition == patternSize - 1)
                {
                    return reinterpret_cast<intptr_t>(memory) + possibleAddress;
                }

                ++patternPosition;
            }
            else
            {
                if (patternPosition > 0)
                {
                    i = possibleAddress;
                }

                patternPosition = 0;
            }
        }

        return 0;
    }

    /// <summary>
    /// Some ntdll stuff, not really useful at the moment.
    /// </summary>
    namespace NT
    {
        static const unsigned char PatSyscallCall[] =
        {
#ifdef _WIN64
            0xB8, '?', '?', '?', '?',                   // MOV EAX, syscallid
            0xF6, 0x04, 0x25, '?', '?', '?', '?', 0x01, // TEST unknown, 1
            0x75, 0x03,                                 // JNE
            0x0F, 0x05,                                 // SYSCALL
            0xC3                                        // RET
#else
            0xB8, '?', '?', '?', '?', // MOV EBX, syscallid
            0xBA, '?', '?', '?', '?', // MOV EDX, syscallstub
            0xFF, 0xD2,               // CALL EDX
            0xC2                      // RET
#endif
        };

        /// <summary>
        /// Find the execution part of a syscall by pattern matching.
        /// </summary>
        /// <param name="procName">Syscall name</param>
        /// <returns>Pointer to syscall or nullptr</returns>
        __forceinline intptr_t FindSycallCall(FNV1A::fnvhash procName) noexcept
        {
            if (auto proc = RtFnGetProcAddress(CX_IFnv1a("ntdll.dll"), procName))
            {
                // TODO: make function size non static (32)
                return SearchPattern(PatSyscallCall, sizeof(PatSyscallCall), proc, 32);
            }

            return 0;
        }

        /// <summary>
        /// Get a pointer to the syscall execution jump.
        /// </summary>
        /// <returns>Stub pointer</returns>
        __forceinline void* GetSycallStub32() noexcept
        {
            if (auto addr = FindSycallCall(CX_Fnv1a("NtAllocateVirtualMemory")))
            {
                return reinterpret_cast<void*>(*reinterpret_cast<unsigned long*>(addr + 0x6));
            }

            return nullptr;
        }

        /// <summary>
        /// Get the id of a syscall.
        /// </summary>
        /// <param name="name">Syscall name</param>
        /// <returns>Id of the syscall</returns>
        __forceinline unsigned long GetSyscallId(FNV1A::fnvhash name) noexcept
        {
            if (const auto addr = FindSycallCall(name))
            {
                return *reinterpret_cast<unsigned long*>(addr + 0x1);
            }

            return -1;
        }
    }
}