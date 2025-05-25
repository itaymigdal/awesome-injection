*Centralized resource for listing and organizing known injection techniques and POCs*

- [Introduction](#introduction)
- [Linux Injection](#linux-injection)
  - [Process Spawning](#process-spawning)
      - [LD\_PRELOAD](#ld_preload)
  - [Process Injection](#process-injection)
      - [PTRACE](#ptrace)
      - [Proc Memory](#proc-memory)
- [Windows Injection](#windows-injection)
  - [Process Spawning](#process-spawning-1)
      - [Process Hollowing](#process-hollowing)
      - [Transacted Hollowing](#transacted-hollowing)
      - [Process Doppelganging](#process-doppelganging)
      - [Process Herpaderping](#process-herpaderping)
      - [Process Ghosting](#process-ghosting)
      - [Early Bird](#early-bird)
      - [EntryPoint Patching](#entrypoint-patching)
      - [Ruy-Lopez](#ruy-lopez)
      - [Early Cascade Injection](#early-cascade-injection)
      - [Kernel Callback Table Injection](#kernel-callback-table-injection)
  - [Process Injection](#process-injection-1)
      - [Classic Dll Injection](#classic-dll-injection)
      - [Classic Shellcode Injection](#classic-shellcode-injection)
      - [Dll Injection via SetWindowsHookEx](#dll-injection-via-setwindowshookex)
      - [Reflective Dll Injection](#reflective-dll-injection)
      - [PE Injection](#pe-injection)
      - [Section Mapping Injection](#section-mapping-injection)
      - [APC Queue Injection](#apc-queue-injection)
      - [Thread Execution Hijacking](#thread-execution-hijacking)
      - [Atom Bombing Injection](#atom-bombing-injection)
      - [Mocking jay Injection](#mocking-jay-injection)
      - [ListPlanting Injection](#listplanting-injection)
      - [Extra Window Memory Injection](#extra-window-memory-injection)
      - [ThreadlessInject](#threadlessinject)
      - [EPI](#epi)
      - [DllNotification Injection](#dllnotification-injection)
      - [D1rkInject](#d1rkinject)
      - [NtQueueAPCThreadEx Gadget Injection](#ntqueueapcthreadex-gadget-injection)
      - [Dirty-Vanity](#dirty-vanity)
      - [Function Stomping](#function-stomping)
      - [Caro-Kann](#caro-kann)
      - [Stack Bombing](#stack-bombing)
      - [Ghost Injector](#ghost-injector)
      - [Ghost Writing](#ghost-writing)
      - [Ghost Writing 2](#ghost-writing-2)
      - [Mapping Injection with Instrumentation Callback](#mapping-injection-with-instrumentation-callback)
      - [SetProcessInjection](#setprocessinjection)
      - [Pool Party Injection](#pool-party-injection)
      - [Thread Name Calling](#thread-name-calling)
      - [Waiting Thread Hijacking](#waiting-thread-hijacking)
      - [RedirectThread Context Injection](#redirectthread-context-injection)

# Introduction
I've been thinking about putting together a list of process injection techniques and ingenious POCs because I haven't found a decent one. This list focuses on process-spawning injection methods and actual process injection, excluding pre-execution techniques (e.g. AppCert and AppInit Dlls), and self-injection techniques.

**PRs are welcome to help me maintain and extend this list!**

# Linux Injection

## Process Spawning

#### LD_PRELOAD
- https://attack.mitre.org/techniques/T1574/006/

## Process Injection

#### PTRACE
- https://attack.mitre.org/techniques/T1055/008/
- https://github.com/kubo/injector

#### Proc Memory
- https://attack.mitre.org/techniques/T1055/009/
- https://github.com/DavidBuchanan314/dlinject
- https://github.com/AonCyberLabs/Cexigua

# Windows Injection

## Process Spawning

#### Process Hollowing
- https://attack.mitre.org/techniques/T1055/012/
- https://github.com/m0n0ph1/Process-Hollowing

#### Transacted Hollowing
- https://github.com/hasherezade/transacted_hollowing

#### Process Doppelganging
- https://attack.mitre.org/techniques/T1055/013/
- https://github.com/hasherezade/process_doppelganging

#### Process Herpaderping 
- https://github.com/jxy-s/herpaderping

#### Process Ghosting
- https://github.com/hasherezade/process_ghosting

#### Early Bird
- https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/
- https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection

#### EntryPoint Patching
- https://www.ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx

#### Ruy-Lopez
- https://github.com/S3cur3Th1sSh1t/Ruy-Lopez

#### Early Cascade Injection
- https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/
- https://github.com/Cracked5pider/earlycascade-injection

#### Kernel Callback Table Injection
- https://github.com/0xHossam/KernelCallbackTable-Injection-PoC

## Process Injection

#### Classic Dll Injection
- https://attack.mitre.org/techniques/T1055/001/
- https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection

#### Classic Shellcode Injection
- https://www.ired.team/offensive-security/code-injection-process-injection/process-injection

#### Dll Injection via SetWindowsHookEx
- https://github.com/DrNseven/SetWindowsHookEx-Injector
  
#### Reflective Dll Injection
- https://attack.mitre.org/techniques/T1055/001/
- https://github.com/stephenfewer/ReflectiveDLLInjection
- https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection

#### PE Injection
- https://attack.mitre.org/techniques/T1055/002/
- https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes

#### Section Mapping Injection
- https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection

#### APC Queue Injection
- https://attack.mitre.org/techniques/T1055/004/
- https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection  

#### Thread Execution Hijacking 
- https://attack.mitre.org/techniques/T1055/003/
- https://www.ired.team/offensive-security/code-injection-process-injection/injecting-to-remote-process-via-thread-hijacking
  
#### Atom Bombing Injection
- https://github.com/BreakingMalwareResearch/atom-bombing

#### Mocking jay Injection
- https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution

#### ListPlanting Injection
- https://attack.mitre.org/techniques/T1055/015/
- https://cocomelonc.github.io/malware/2022/11/27/malware-tricks-24.html

#### Extra Window Memory Injection
- https://attack.mitre.org/techniques/T1055/011/
- https://github.com/BreakingMalware/PowerLoaderEx
  
#### ThreadlessInject
- https://github.com/CCob/ThreadlessInject
 
#### EPI
- https://github.com/Kudaes/EPI

#### DllNotification Injection
- https://github.com/Dec0ne/DllNotificationInjection

#### D1rkInject
- https://github.com/TheD1rkMtr/D1rkInject

#### NtQueueAPCThreadEx Gadget Injection
- https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection

#### Dirty-Vanity
- https://github.com/deepinstinct/Dirty-Vanity

#### Function Stomping
- https://github.com/Idov31/FunctionStomping

#### Caro-Kann
- https://github.com/S3cur3Th1sSh1t/Caro-Kann

#### Stack Bombing
- https://github.com/maziland/StackBombing

#### Ghost Injector
- https://github.com/woldann/GhostInjector

#### Ghost Writing
- https://github.com/c0de90e7/GhostWriting
- https://blog.sevagas.com/IMG/pdf/code_injection_series_part5.pdf

#### Ghost Writing 2
- https://github.com/fern89/ghostwriting-2

#### Mapping Injection with Instrumentation Callback
- https://github.com/antonioCoco/Mapping-Injection

#### SetProcessInjection
- https://github.com/OtterHacker/SetProcessInjection
  
#### Pool Party Injection
- https://www.safebreach.com/blog/process-injection-using-windows-thread-pools
- https://github.com/SafeBreach-Labs/PoolParty

#### Thread Name Calling
- https://github.com/hasherezade/thread_namecalling
- https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/

#### Waiting Thread Hijacking
- https://github.com/hasherezade/waiting_thread_hijacking
- https://research.checkpoint.com/2025/waiting-thread-hijacking/

#### RedirectThread Context Injection
- https://blog.fndsec.net/2025/05/16/the-context-only-attack-surface/
- https://github.com/Friends-Security/RedirectThread
