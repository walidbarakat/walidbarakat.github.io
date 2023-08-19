---
layout: post
title: 'Truebot (aka silence) botnet analysis'
date: 2023-08-16
tags:
  - Malware Analysis
  - Reverse Engineering
permalink: /truebot_analysis/
toc: true
---

# Introduction

Few months ago warnings were issued around increasing activities of truebot and maybe the [CISA report](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-187a) is an arousing one .. and actually it turns out that truebot isn't much complex to analysis although it tried to use some anti-analysis techniques. Truebot is mainly used as a downloader or first stage to engage on the victim machine and was used in phishing campain luring victims to download the binary which shielded by adobe acrobate icon. first thing i was surprised/not-surprised by the pile of junky code that was put there to confuse or trash the analysist. unfortunately i spent some time looking inside that code and it really didn't turnout to be useful. However, let's start by looking at the useful part of the code and check "statically" how the sample under investigation works.  

# Infecting and Anti-emulation

![First real steps](/images/first-truebot-steps.png)  

First we can see what seems to be a try to detect if the process is attached to `x64dbg` by detecting `x64` or `X64` in the running process name, whatever the intention of that check .. obviously Truebot will immediatly spawn an innocent `calc.exe` process and terminate its own process. but since that's obvious in the decompiled/disassembled code so analysist can trick Truebot to not detect that. In case this the first occurance of infection - which means the victim just clicked the "fake" pdf file - it just prompts error message as shown in the second if statement in the above screenshot then checks if `AVG` or `avast` is present and if not here comes the step that start the real work .. it copies itself into file `C:\Intel\RuntimeBrokere.exe` and spawn a new process from that file and terminates the current running process as shown below.

![Check for AV and copy to another file](/images/copy_to_legit_file.png)

From here we're talking about the new spawned process from `C:\Intel\RuntimeBrokere.exe` .. 

Another Anti-emulation test is used which is old but can be still effective in a way that most of AV emulators and probably other average emulators doesn't really implement every API and not even veridct if that called API by the malware should return a certain value. so as shown below you can see windows API like `CallNamedPipeW`, `WaitNamedPipeW`, `TransactNamedPipe`and `EraseTape`.  

![Anti-emulation](/images/anti-emulation(1).png)  

The above mentioned APIs can be seen in the screenshot but when we look at the last line, the malware is checking for specific error values that should be raised on normal execution environment!

The running process ensures that only one instance is running by initiating a hardcoded mutex named `OrionStartWorld#666` so if another process of it is spawned it will terminates. then checks for internet connectivity to `google.com` then proceed or sleep and try again till a connection is confirmed.
Then first before starting the real action the malware is collecting OS information like OS version, DNS domain name and DNS host name.

![1](/images/truebot_misc_1.png)

# C&C

After the above is done, malware starts to decrypt it's C&C information using RC4 algorithm with hardcoded key `qaTuMuseBaMuQoNe` and base64 encoded host and panel are decrypted prespectivily `essadonio.com` and `/538332.php`

![C2 details](/images/truebot_C2.png)

Then it waits for the commands, as it seems from the static analysis commands expected are : 
  1) `LSEL` whic causes the process to kill itself (details..) 

![truebot_lsel](/images/truebot_lsel_c2_cmd.png)

  2) `TFOUN` which indicates an array of commands to be executed :
    - `EFE` download payload, decrypt with RC4, copy it into a PE file `IntelCpHDCPSvc<victime-guid>.exe` and execute it as a separate process.

![truebot_efe](/images/truebot_efe_c2_cmd.png)

    - `S66` download, decrypt with RC4, and inject shellcode to `cmd.exe`
    - `Z66` run shellcode

![truebot_6ss_z66](/images/truebot_s66_z66_c2_cmd.png)

# Conclusion & Resources

sample : [717beedcd2431785a0f59d194e47970e9544fbf398d462a305f6ad9a1b1100cb](https://www.unpac.me/results/8d1eb4c3-cbb0-4b32-8d52-6f142c836d0f?hash=717beedcd2431785a0f59d194e47970e9544fbf398d462a305f6ad9a1b1100cb#/)

Unfortunately there are missing points that holds full analysis for truebot, like i can't inspect the C&C communication and there's no explanation why the HUGE amout of trash code, plus the logic it self seems not consistent i.e why using global mutex `OrionStartWorld#666` after creating the new process `C:\Intel\RuntimeBrokere.exe` not after and another few points. but it's always good to check these resources for better info and more detailed analysis like [Robert Giczewski's analysis](https://malware.love/malware_analysis/reverse_engineering/2023/03/31/analyzing-truebot-capabilities.html), [The DFIR report](https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/) and [OALab analysis](https://research.openanalysis.net/truebot/config/triage/2023/07/13/truebot.html)

Cheers!


