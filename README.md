# Position_Independent_Backdoor
This project contains methodology of creating position independent code that is used to extract shellcode from the generated binary.
Position independent shellcode could be injected in any process for evading defenses and creating backdoors.
This code is called position independent code because it doesn't depend on a linker to resolve external dependencies like importing dlls and using functions inside.


It uses cmd to get commands from the c3 server after every 10 seconds and execute it on the system.
With the help of MSVC we can convert this code to .asm file and then link those assembly instructions to a binary.
After that we can extract shellcode from the .text section of that binary.


A demo video provided that takes commands from c3 and execute on victim system:


https://user-images.githubusercontent.com/34940939/162588916-1950dcda-4c3c-4117-879a-2f8a96a9c5ab.mp4

