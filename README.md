# Position_Independent_Backdoor
This project contains methodology of creating position independent code that is used to extract shellcode from the generated binary.
Position independent shellcode could be injected in any process for evading defenses and creating backdoors.
This code is called position independent code because it doesn't depend on a linker to resolve external dependencies like importing dlls and using functions inside.


It uses cmd to get commands from the c3 server after every 6 seconds and execute it on the system.
With the help of MSVC we can convert this code to .asm file and then link those assembly instructions to a binary.
After that we can extract shellcode from the .text section of that binary.
