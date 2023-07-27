---
layout: post
title: 'PE file headers - introduction'
date: 2023-07-26
tags:
  - PE File
  - Windows internals
permalink: /pe_file_headers_introduction/
toc: true
---

PE (Portable Executable) file is very elementary and interesting area of knowledge for whoever build, debug or reverse engineer an application (or Malware!) on Windows OS .. even though i know there are many good articles to explain PE headers and internals plus [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), i believe the best way to better understand something or topic is to explain it to others. as well, i'll try to explain what i understand about PE internals - using [010 hex editor](https://www.sweetscape.com/download/010editor/) (headers info, mapped and unmapped PE image, ...) in a way that may concern whoever is interested in working with malware samples.

> **_Note:_** beside the hex view for sure, 010 hex editor has a nice executable file template to show PE structures.

# IMAGE_DOS_HEADER

First structure we gonna look at is `struct IMAGE_DOS_HEADER`, it's a 64 byte structure that mostly concers the OS loader. first two bytes of this structure is **WORD MZSignature** which just an ASCII -little endian- value "MZ" aka [Mark Zbikowski](https://www.linkedin.com/in/markzbikowski). as the name indicates, it's just an EXE image signature to facilitate the loader task. other than that comes information - not well documented officially - concerns OS loader for MS-DOS and fewer for Windows system about how many pages the file requires. however, `LONG AddressOfNewExeHeader` is the last 4 bytes of this Dos header structure are the one we will always need as it holds the offest of first byte of the **PE header**!  

![IMAGE_DOS_HEADER_hex_view](/images/image_dos_header_hex_view.png)  

# IMAGE_DOS_STUB

Right after that you can find `struct IMAGE_DOS_STUB`, by default it's a 64 byte long structure and holds a tiny 16-bit MS-DOS program which prints `This program cannot be run in DOS mode` whenever a user execuets an EXE file in MS-DOS environment. but that's the default and it runs only on MS-DOS, i think i need to play around it in more "funny" way and write about it later.

>**_Note:_** For fun in a way or another, you can embed your customise `IMAGE_DOS_STUB` using linker option `/STUB` in Visual studio or can be stripped from the EXE, it's just there for backward compatibility.

![IMAGE_DOS_STUB_hex_view](/images/DOS_stub_and_rich_header.png)

# IMAGE_SECTION_HEADER

Before jumping to PE header, we can see there's `Rich header` located between Dos stub header and PE header .. since the release of Visual Studio 97 SP3, Microsoft has placed this undocumented chunk of data between the DOS and PE headers. unless it's not stripped out by malware author or packer, it can reveal informations about the build environment and the scale of the project. and with a closer look, the header could indicate whether their source code is available more widely or under the control of a single actor. you can read more about this [Virus Bulletin research on mysterious rich header](https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/).  

>**_Note:_** 010 hex editor template shows rich header as part of `struct IMAGE_DOS_STUB`, but that's not correct. I think it happens because the editor just define it as the space of bytes between DOS header and NT header. rich header can be easily identified by finding `Rich` keyword which marks the end of the header, and it's followed by 4 bytes XOR key you can use and start backward dycrypting till `DanS` keyword is reached.  

just one nice thing to mention here to show show rich header became a bit of important info, we can mentions the famous attack on winter olympics 2018. where it was found the rich header of the malware used in the attack was similar to one another samples used by lazarus group before, it was realised later that it was false flag but this shows how rich header can be used as well from attacker prespective.  

# IMAGE_NT_HEADER

The structure that represents PE file header, it contains 4 bytes signature `0x50450000` represents ASCII `PE\0\0`, `struct IMAGE_FILE_HEADER` and `struct IMAGE_OPTIONAL_HEADERXX`. the two Xs at image optional header here to note that `IMAGE_NT_HEADER` can be defined as `IMAGE_NT_HEADERS32` or `IMAGE_NT_HEADERS64` whether `_WIN64` is defined at compile time or not, so you should consider this when looking at the PE file.

```
// defined on Win32
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

// defined on Win64
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```
`IMAGE_FILE_HEADER` defined as :

```
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```
it has a informations for the OS loader like `Machine` which holds the information about the targeted machine, `NumberofSections` it's the size of the section table it's limited to 96 section by the Windows loader! and here we can remember the old nice way of **code caving** that can be used to **infect** another legit PE files on disk for persistency, patching a section characteristics to be writable and executable so the code inside that section can change dynamically or even cracking some program, section size is defined by `DWORD SectionAlignment` which has by default is 4096 bytes or the system page size .. 4096 bytes seems not much but can do a lot of things, let your imagination going through that! we can see also `TimeDataStamp` which tells the time where the image was created by the linker, however, this time stamp can't really be trusted always as Microsoft enabled `/BREPRO` linker flag to used to create "reproducible builds" which intented to make a unique hash id for differents binaries (builds) compiled using the same source code. so to achieve that, timestamps which are changing by nature over all the PE are replaced with the last 4 bytes of that hash .. you can find more info on that point on [Karsten Hahn's youtube channel](https://www.youtube.com/watch?v=8Q_cbAolKGg&t=22s).  

`PointerToSymbolTable` is the offset from the start of the mapped file to the symbol table and `NumberOfSymbols` just holds the number of symbols.

>**_Note:_** when inspecting PE header, `PointerToSymbolTable` will be 0 as Image file doesn't contain symbol table but you can find it in object file.

then we can see `SizeOfOptionalHeader` which specifies size of next structure member of `IMAGE_FILE_HEADER`. followed by `Characteristics` which indicates file attributes i.e DLL, system file or whether the application can handle more than 2GB address space. [Microsoft documentation for more details](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics)  


# IMAGE_OPTIONAL_HEADER

Image optional header is really important for Windows linker and loader as PE loader looks for information provided by that header to be able to load and run the executable file.

>**_Note:_** "optional" here only means other files like object files don't have, but it's essential for PE image files. and it's nice to know that the first 8 members of that header are standard for every [COFF](https://wiki.osdev.org/COFF#:~:text=COFF%20stands%20for%20Common%20Object,of%20the%20program%2C%20such%20as%20.) implementation, so other members of the structure are Microsoft extenstion to that strucure.

`IMAGE_OPTIONAL_HEADER` definition : 

```
typedef struct _IMAGE_OPTIONAL_HEADER {
  // standard members for COFF files ..
  WORD    Magic; // magic number to state if image file is executable for 32, 64 platform or it's a ROM image
  BYTE    MajorLinkerVersion;
  BYTE    MinorLinkerVersion;
  DWORD   SizeOfCode; // size of code section i.e `.text` in bytes or sum of all code sections if more than one exists
  DWORD   SizeOfInitializedData; // size of the initialized data section i.e `.data`, in bytes, or the sum of all such sections if there are multiple initialized data sections
  DWORD   SizeOfUninitializedData; // size of the uninitialized data section i.e `.bss`, in bytes, or the sum of all such sections if there are multiple uninitialized data sections
  DWORD   AddressOfEntryPoint; // pointer to the entry point function, relative to the image base address
  DWORD   BaseOfCode; // pointer to the beginning of the code section, relative to the image base
  DWORD   BaseOfData; // pointer to the beginning of the data section, relative to the image base
  
  // Microsoft NT extension
  DWORD   ImageBase; // preferred address of the first byte of the image when it is loaded in memory. This value is a multiple of 64K bytes
  DWORD   SectionAlignment; // alignment of sections loaded in memory, in bytes. This value must be greater than or equal to the FileAlignment member
  DWORD   FileAlignment; // alignment of the raw data of sections in the image file, in bytes. The value should be a power of 2 between 512 and 64K (inclusive)
  WORD    MajorOperatingSystemVersion;
  WORD    MinorOperatingSystemVersion;
  WORD    MajorImageVersion;
  WORD    MinorImageVersion;
  WORD    MajorSubsystemVersion; 
  WORD    MinorSubsystemVersion;
  DWORD   Win32VersionValue;
  DWORD   SizeOfImage; // The size of the image, in bytes, including all headers. Must be a multiple of SectionAlignment
  DWORD   SizeOfHeaders;
  DWORD   CheckSum; // The image file checksum
  WORD    Subsystem; // The subsystem required to run this image
  WORD    DllCharacteristics;
  DWORD   SizeOfStackReserve; // The number of bytes to reserve for the stack. Only the memory specified by the SizeOfStackCommit member is committed at load time
  DWORD   SizeOfStackCommit; // The number of bytes to commit for the stack
  DWORD   SizeOfHeapReserve; // The number of bytes to reserve for the local heap. Only the memory specified by the SizeOfHeapCommit member is committed at load time
  DWORD   SizeOfHeapCommit; The number of bytes to commit for the local heap
  DWORD   LoaderFlags; // obsolete
  DWORD   NumberOfRvaAndSizes; // number of entries in the following DataDirctory .. 
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // directory entries sizes and relative virtual addresses
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```
it's worth to note that 1) `AddressOfEntryPoint` for exe file is the pointer for the starting address aka `Start` function not `Main` or `WinMain`. for device driver, it will point to initialization functions, and for DLL, it points for the optional entry point. 2) As well for `ImageBase` value is not true any more as ASLR will stop exectuable to have predictable addresses in memory. 3) `SizeOfHeaders` value is the sum of the DOS stub, PE header (NT Headers), and section headers sizes rounded up to a multiple of FileAlignment. 4) `Subsystem` which indicates which [subSystem](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32) is required to run this image. 5) `CheckSum` is used to validate driver at load time and DLLs loaded at boot time or loaded into a critical system process.

>**_Note:_**: if you're writing a PE parser or a debugger, try to not be too much strict when following the speification here. and remember in that case the PE headers are also a possible dagger in the hands of Malware author ;)

# PE sections

Now we will take a look on the PE sections (.text, .data and so on ..) i assume you know already what kind of data the linker puts in each section. if not you can use google search or for more advanced infomration i really would recommend [Computer Systems book - chapter 7](https://www.amazon.com/Computer-Systems-Programmers-Perspective-3rd/dp/013409266X) and [advanced c and c++ compiling book](https://www.amazon.com/Advanced-C-Compiling-Milan-Stevanovic/dp/1430266678) .. and these aren't affiliation links xD

you can see the list of all sections in the PE under an array of `IMAGE_SECTION_HEADER` structure where the size of the array is the number of sections 

```
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

and in 010 hex editor it look like this :

![image_secion_header](/images/image_section_header.png)

you can see the first `IMAGE_SECTION_HEADER SectionHeaders[0]` is represnting `.text` section and highlighted in dark yellow .. as well highlighted `DWORD VirtualAddress` which point to the virtual relative address or offset of `.text` section and `DWORD PointerToRawData` which points to the offset of `.text` section on disk (aka raw data or image not executed yet) and this the value where we can find `.text` section in hex editor, so if we look at offset `0x400` we can see it

![raw_address_on_disk](/images/raw_address_text.png)

but `VirtualAddress` is just a relative address to the image base address which will most likely have a different address when loaded into memory ... but if we look at IDA hext view for example :

![IDA_raw_hex_view](/images/IDA_hex_view_on_disk.png)

you can see the offset is `0x401000` not `0x400` or even `0x1000`! why? because IDA is trying to show the address which is likely to be in the memory but as we open the image on disk and the image base which is by default is `0x400000` so IDA calculate the new RVA (Relative Virtual Address) of that section and show it to you.

>**_NOTE:_**: if you're using IDA for static analysis and in the same time you're using another debugger for dynamic analysis and you can't easily find the address of a function for example in the debugget to match what you see in IDA, you can rebase the whole program in IDA basic on the the image address you see in the memory and use Edit->Segments->Rebase program and enter the value of the new image base.

one another thing, remember `AddressOfEntryPoint` from `IMAGE_OPTIONAL_HEADER`? let's check it's address as entry point function is part of the `.text` section anyway

![AddressOfEntryPoint_hex_view](/images/addrs_of_entry_point_hex_view.png)

you can see the offset is `0x7244` which means "if" the `.text` function is loaded at offset `0x1000` then entry point offset will be `0x7244` but since we know that's not the case, so we can see it's just a caluclated relative address as well, then the relative address for entry point is `0x6244`. at the very right of the line you can see 010 added in comment column `.text FOA = 0x6644` i think that easy to guess what this address mean now .. it's the relative address for entry point but on disk or raw address right now. 

>**_Note_**: I think FOA here means "Form Of Address", please let me know if it means something different in 010 hex editor.

Interesting thing about `DWORD SizeOfRawData` value, it can be used as anti-unpacking technique by overwrite it with invalid or not aligned value as it's a subject to automatic rounding up by the OS and it's possible to produce a section whose entrypoint appears to reside in purely virtual memory, but because of rounding, will have physical data to execute. I found this [paper](https://pferrie.tripod.com/papers/unpackers.pdf) as really nice for inspiring what can go wrong because of PE structure members.

after you can see the `IMAGE_SECTION_DATA` structures, but i don't think it's relevant here as it contains only the data relevant to each section.

let's take a break here .. and next time i'll try to dig into PE import table and exports


