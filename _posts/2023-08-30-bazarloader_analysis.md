---
layout: post
title: 'Baza(r?) loader static analysis - 1'
date: 2023-08-30
tags:
  - Malware Analysis
  - Reverse Engineering
permalink: /bazarloader_static_analysis_1/
toc: true
---

Baza - or Bazar - loader is a sophisticated piece of malware that emerged at 2020 used by a threat actor through a phishing campain using [Sendgrid email marketing platform](https://sendgrid.com/). back then, a report was published back then by [cybereason](https://www.cybereason.com/blog/research/a-bazar-of-tricks-following-team9s-development-cycles) claims the variant samples shows that it's an under development still although many tricks used. last week i got [the latest sample from MalwareBazaar](https://bazaar.abuse.ch/sample/7ccd2066aa7194f5ae343eb6fa26ac0db06e3380af47974f86a20f0db98f1230/) and Although there are already published nice analysis and reports on Bazar loader, will try to make some anaylsis on an implementation level, let's say like a dissecting job which could be boring. as well no promises will be nothing really useful unless you're like me a beginner and wondering what's going on inside malware authors mind hoping i will learn something new and show something that maybe interesting.

As a start, malware is setting a timer as a way to dodge sand boxes and then intiate it's main activity which returns a status - only 1 or 0 - and the process terminates only is 1 is returned.

![start_bazarloader](/images/start_bazarloader.png)

Malware starts by constructing it's own import table by allocating a 4560 Bytes on the heap using `VirtualAlloc`. However, Bazar loader using API hashing - constructing import table step isn't an exception - and string encoding everywehere, which makes static analysis or rather opening up to get a closer a look a not pleasing experience, but i think for a beginner would be an eyes opening.

![virtualalloc_resolve](/images/resolve_virtualalloc.png)

We can see in the screenshot resolving `VirtualAlloc` call, as well the most called function - exactly 243 times - and responsible for resolving any API call. so let's open it up and see how it works.

![resolve_api_hash_n_addr](/images/resolve_api_addr_bazarloader.png)

It checks if the import table is constructed and the provided index (API address entry) is valid so it returns the value at that index. if that's not the case, the API is retrieved using the hash through `func_get_api_by_hash`, it takes 3 parameters including the desired aPI hash and couples of flags to direct the function which DLL has the API, the function get the API address or base address for kernel32 DLL .. it all depends on the combination of flags were provided.

![get_api_by_hash](/images/api_hash_n_addr_bazarloader.png)

*Kernel32.dll* base address is stored as well as a global variable to be used when needed and obviously it's retrieved `func_get_kernel32_dll_base_addr` if not defined and in the heart of this function is the function that facilitate the whole technique, i called it `getdll_base` which takes the DLL hash as an input.

![getdll_base](/images/getdll_base_bazarloader.png)

Here we would go theoritical a bit .. When a process is created, Windows kernel - among other things - populating [**PEB structure**](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb), a pointer to PEB structure is stored on 32bit system in FS:[0x30] and on 64bit system in GS:[0x60]. we can consider it as a the lowest-level in user mode and highest-level in kernel mode of knowledge about the newly created process. although it's not well documented structure but i find [verigilius project](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2110%2021H2%20(November%202021%20Update)/_PEB) is a good one to understand it. it's crucial structure though as it can be leveraged by malwares authors to provide their malware some "self-awareness". the part of interest here is [**_PEB_LDR_DATA**](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2110%2021H2%20(November%202021%20Update)/_PEB_LDR_DATA) structure which contains a 3 doubly linked lists `InLoadOrderModuleList`, `InMemoryOrderModuleList` and `InInitializationOrderModuleList` each of [**_LDR_DATA_TABLE_ENTRY**](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2110%2021H2%20(November%202021%20Update)/_LDR_DATA_TABLE_ENTRY) structure and contains information about loaded DLLs but in different order. each entry contains back pointer "Blink" and forward link "Flink" allow to iterate entries.

Here's a really nice visualization for these structure. credits to [Christophe Tafani-Dereeper](https://blog.christophetd.fr/).

![LDR_DATA_TABLE_ENTRY](/images/LDR_DATA_TABLE_ENTRY-chaining.png)

Back to bazar loader, it gets the base address for the desired DLL through access `InLoadOrderModuleList` and move through `Flink` pointer to get loaded DLL `BaseDllName` then hash it, if matches it just return `DllBase` value which will be the base address in memory for the DLL.

>**_NOTE_** luckily all API and DLL hashes - at least in the analysed sample - can be found on [this github repo](https://github.com/hidd3ncod3s/WindowsAPIhash).

Taking a step back, after Bazar loader is done with allocating it's own IAT and *Kernel32.dll* base address global variable it goes to populating a set of global variables with addresses of "some" the APIs will be used later during run time.

![api_addresses_globales](/images/api_addr_bazarloader.png)

It follows a pattern of the following .. 1) decrypt - or better to say decode - DLL name -> 2) get address of `LoadLibraryA` -> 3) load DLL to get a handle to it -> 4) decrypt - or better to say decode - API names -> 5) get address of `GetProcAddress` -> 6) resolve API address in memory and store it. It gets API addresses from *kernel32.dll*, *api32.dll*, *advapi32.dll*, *shlwapi.dll*, *wininet.dll*, *Shell32.dll* and others i didn't go over decoding them as we got the idea already! maybe it's noteworthy that this step the malware terminates the process if any of the sub-steps failed.

Another trick in the bazar is [DLL unhooking](https://unprotect.it/technique/dll-unhooking/) to evade EDRs and API hooking by loading it's own fresh (non-hooked in case the memory loaded file is hooked) copy of `ntdll.dll` from disk because it's the usually hooked DLL because it has the navtive APIs so it's the closest to the kernel, i don't think it's really the best way in case higher level DLLs were hooked like `kernel32.dll` was hooked or an EDR is monitoring open file handles.

![get_fresh_ntdll](/images/get_fresh_ntdll_bazar_loader.png)

then it allocate a heap memory to copy `ntdll.dll` content to it so it can resolve the native APIs within the process private address space. However, as it seems obvious right now that shellcode will be used, so let's see how malware get native function ordinals from `ntdll.dll` by getting back again to PE structure, and keep in mind we have a handle to `ntdll.dll` in memory which will act as the DLL base address points to `IMAGE_DOS_HEADER`, so from `IMAGE_DOS_HEADER` we have the pointer to `IMAGE_NT_HEADERS` - offset of "PE" - and it has RVA `0x3C` and by checking that structure it looks to have `_IMAGE_OPTIONAL_HEADER` which is the one on the right direction.

>**_NOTE_** structures and indexes may differ on 32bit and 64bit systems, like we saw for PEB offset.

```
struct _IMAGE_NT_HEADERS64
{
    ULONG Signature;                                //0x0
    struct _IMAGE_FILE_HEADER FileHeader;           //0x4
    struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader; //0x18
};

```
```
//0xf0 bytes (sizeof)
struct _IMAGE_OPTIONAL_HEADER64
{
    USHORT Magic;                     //0x0
    UCHAR MajorLinkerVersion;         //0x2
    UCHAR MinorLinkerVersion;         //0x3
    ULONG SizeOfCode;                 //0x4
    ULONG SizeOfInitializedData;      //0x8
    ULONG SizeOfUninitializedData;    //0xc
    ULONG AddressOfEntryPoint;        //0x10
    ULONG BaseOfCode;                 //0x14
    ULONGLONG ImageBase;              //0x18
    ULONG SectionAlignment;           //0x20
    ULONG FileAlignment;              //0x24

    ......

    struct _IMAGE_DATA_DIRECTORY DataDirectory[16];  //0x70 <------
};

```
From the above structures one can calculate the address for `DataDirectory[0]` which is `_IMAGE_EXPORT_DIRECTORY` structure and the one of interest as it's the one contains among others the structure of DLL exported functions info. which will be the same - on 64 bit system - as the malware does already and will see in a moment.

let's take a quick look on `_IMAGE_EXPORT_DIRECTORY` to get an idea what malware is looking for ...

```
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image

} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

```
**AddressOfFunctions** : array that contains the offset values of the API addresses.
**AddressOfNames** : array that contains API name’s pointers.
**AddressOfNameOrdinals** : array containing the ordinal numbers to get the address position of the API function from the index of the API name.

The above three arrays can be used - in relative to the DLL base address - to search an API address providing API name, `AddressOfNames` which an array of string pointers and once you get the name of the desired API, the index of that string pointer can be used to access the offset of its ordinal number from `AddressOfNameOrdinals` and finally that ordinal number can be used to access `AddressOfFunctions` and as we are accessing pointers in raw memory, we should always remember about the pointer size factor in accessing specific address. so to access an API address from `AddressOfFunctions` let's say it's oridnal number is `0x123` so *API address = (AddressOfFunctions offset) + (pointer size * 0x123)*. so if these info are presented already, now will be too plain how the malware here implementing that :

![get_export_directory](/images/cal_native_func_ordinal_bazar_loader.png)

Then a series of decoding API names will start with calling API hasing resolving function again and again to get some native API address from `ntdll.dll` and then malware doing another trick to evade EDR by making sure these native APIs are unhooked by copying the first 5 bytes from the "fresh" API that was loaded from disk to replace the first 5 bytes of the same API in memory to overwrite hook instructions (if exist), first changing memory protection from being execute and read to be execute, read and write. later it restores execute and read protection.

![nt_API_unhook](/images/unhooking_nt_api_bazar.png)

.. to be continued















