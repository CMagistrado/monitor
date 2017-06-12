# Disassembles starting bytes of API calls to see if they match monitor's assumptions

import sys
from ctypes import windll, string_at
from binascii import hexlify

def dis(name):
    print name

    libaddr = windll.kernel32.GetModuleHandleA('kernel32')
    addr = windll.kernel32.GetProcAddress(libaddr,name)
    #print hex(addr)

    byte_content = string_at(addr, 8)
    rv = hexlify(byte_content)
    for i in range(0,len(rv),2):
        sys.stdout.write(rv[i:i+2])
        sys.stdout.write(' ')
    print '\n'


# Hooked by Cuckoo
dis('CreateDirectoryW')
dis('CreateProcessInternalW')
dis('Module32NextW')
dis('FindResourceExW')

print '==============================='

# I'm adding
#dis('InitializeCriticalSection')
dis('EnterCriticalSection')
#dis('LeaveCrtiicalSection')
#dis('GetProcessHeap')
#dis('GetProcAddress')
