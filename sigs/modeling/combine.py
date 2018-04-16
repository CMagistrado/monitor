import sys
import os
import subprocess

# Keep track of functions we've already outputted
written = set()

def grep(full,api):
    found = None
    try:
        out = subprocess.check_output(['grep', '-wn','^'+api,full])
        found = int(out.split(':')[0])
    # API call wasn't found
    except subprocess.CalledProcessError:
        sys.stderr.write('   {0} was not found in {1}\n'.format(api,full))

    return found

# Retrieve API signature from file
def get_sig(full,api):
    global written

    found = None
    foundA = None
    foundW = None

    # Find API call in signature file
    if api not in written:
        found = grep(full,api)

    # Try adding 'A' and 'W' to the ends of the call too
    if api+'A' not in written:
        foundA = grep(full,api+'A')
    if api+'W' not in written:
        foundW = grep(full,api+'W')

    # Get signatures for all possibly found calls
    for e,f in enumerate([found,foundA,foundW]):
        # No signature was found
        if f is None:
            continue

        f = int(f)

        # Add API call to written set
        if e == 0:
            written.add(api)
        elif e == 1:
            written.add(api+'A')
        elif e == 2:
            written.add(api+'W')

        # Get signature of API call
        with open(full,'r') as fr:
            line = None

            # Fast-forward to line number
            for i in range(f):
                line = fr.readline()

            newline = 0
            done = False
            #vishal: made changes to the logic within the while loop to add the assembly instruction into the signatures file
            while True:
                # If end of file
                if not line:
                    break
                #vishal: _flag is for checking whether we've reached the Pre:: category
                _flag=False
                line = line.replace('\r','')
                line = line.replace('\n','')
                if line.lstrip(' ').startswith('Pre::'):
                    _flag=True
                if line == '':
                    newline += 1
                else:
                    newline = 0

                # Logic for adding the Pre part        
                if newline == 2:
                    # vishal: This signature doesn't have a Pre category, we'll write a new one
                    if not done:
                        sys.stdout.write('''Pre::

    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif


''')
                    else:
                        sys.stdout.write('\n')
                    break

                elif _flag:
                    # vishal: We're prepending the PC logic to the existing Pre:: 
                    sys.stdout.write(line + '\n\n'+'''    uintptr_t eip;
    #if !__x86_64__
      __asm__ volatile("movl 4(%%ebp), %0" : "=r" (eip));
    #else
      eip=0;
    #endif
''')
                    done=True
                # vishal: we'll write back whatever we found in the signature file
                else:
                    sys.stdout.write(line + '\n')

                # Get next line
                line = fr.readline()

def get_files():
    for f in os.listdir(os.getcwd()):
        if '.txt' == f[-4:]:
            yield os.path.join(f)

def usage():
    print 'usage: python combine.py sigs.rst-full'
    sys.exit(1)

def _main():
    if len(sys.argv) != 2:
        usage()

    # Get file full of *all* signatures
    full = sys.argv[1]

    # Print out signature heading
    sys.stdout.write('Signature::\n\n')
    sys.stdout.write('    * Calling convention: WINAPI\n')
    sys.stdout.write('    * Category: none\n\n\n')

    # Get list of functions to hook
    fns = get_files()

    # Iterate over API list
    for fn in fns:
        sys.stderr.write('Scanning {0}\n'.format(fn))

        # For each API call in each list
        with open(fn,'r') as fr:
            for line in fr:
                api = line.strip('\r\n')

                # Retrieve API signature from file
                get_sig(full,api)

if __name__ == '__main__':
    _main()
