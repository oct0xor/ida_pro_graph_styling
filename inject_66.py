# Copyright (C) 2015 oct0xor
# 
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 2.0.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License 2.0 for more details.
# 
# A copy of the GPL 2.0 should have been included with the program.
# If not, see http ://www.gnu.org/licenses/

import sys, struct
from ctypes import * 

PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM = (0x1000 | 0x2000)
PAGE_EXECUTE_READWRITE = 0x00000040

TH32CS_SNAPMODULE = 0x00000008

class MODULEENTRY32(Structure):
    _fields_ = [('dwSize' , c_long), 
                ('th32ModuleID' , c_long),
                ('th32ProcessID' , c_long),
                ('GlblcntUsage' , c_long),
                ('ProccntUsage' , c_long),
                ('modBaseAddr' , c_long),
                ('modBaseSize' , c_long), 
                ('hModule' , c_void_p),
                ('szModule' , c_char * 256),
                ('szExePath' , c_char * 260)]

kernel32 = windll.kernel32

CreateToolhelp32Snapshot= windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = c_long
CreateToolhelp32Snapshot.argtypes = [c_int , c_int]

Module32First = windll.kernel32.Module32First
Module32First.argtypes = [c_void_p , POINTER(MODULEENTRY32)]
Module32First.rettype = c_int

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [c_void_p]
CloseHandle.rettype = c_int

def get_proc_base(ProcessID):
    hModuleSnap = c_void_p(0)
    me32 = MODULEENTRY32()
    me32.dwSize = sizeof(MODULEENTRY32)
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID)

    ret = Module32First(hModuleSnap, pointer(me32))

    CloseHandle(hModuleSnap)
    return me32.modBaseAddr

def make_jump(start, target, length):
    if start < target:
        buf = '\xE9' + struct.pack("<L", target - start - 5)
        buf += '\x90' * (length - len(buf))
    else:
        buf = '\xE9' + struct.pack("<L", (target - start - 5) & 0xFFFFFFFF)
        buf += '\x90' * (length - len(buf))
    return buf

pid = int(sys.argv[1])

process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid) 

base = get_proc_base(pid)

payload_size = 0x100

mem = kernel32.VirtualAllocEx(process, 0, payload_size, VIRTUAL_MEM, PAGE_EXECUTE_READWRITE) 

payload = '80F905751C8B4424288B40013D63616C6C750EB1170FB70578336C00E94F9053000FB70578336C00E95B905300909090'.decode('hex')

kernel32.WriteProcessMemory(process, mem, payload, len(payload), 0x0)

hook = make_jump(base + 0x13706B, mem, 7)

kernel32.WriteProcessMemory(process, base + 0x13706B, hook, len(hook), 0x0)

jmp = make_jump(mem + 0x1C, base + 0x137072, 5)

kernel32.WriteProcessMemory(process, mem + 0x1C, jmp, len(jmp), 0x0)

jmp = make_jump(mem + 0x28, base + 0x137072, 5)

kernel32.WriteProcessMemory(process, mem + 0x28, jmp, len(jmp), 0x0)

movzx = '\x0F\xB7\x05' + struct.pack("<L", base + 0x2BAB08)

kernel32.WriteProcessMemory(process, mem + 0x15, movzx, len(movzx), 0x0)

kernel32.WriteProcessMemory(process, mem + 0x21, movzx, len(movzx), 0x0)