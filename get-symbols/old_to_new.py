# Takes the old traced API calls and converts them to new format
import sys
import os

from subprocess import check_output, CalledProcessError

def get_rst_files(path):
    key = '.rst'

    for root, dirs, files in os.walk(path):
        for f in files:
            if key == f[-len(key):]:
                yield os.path.join(root,f)

def usage():
    print 'usage: python old_to_new.py old-folder/ sigs.rst-full > sigs.rst-old-stable'
    sys.exit(1)

def _main():
    if len(sys.argv) != 3:
        usage()

    # Parse arguments
    old = sys.argv[1]
    new_fn = sys.argv[2]

    # Read in old APIs hooked
    old_api = list()
    old_fns = get_rst_files(old)
    for f in old_fns:
        with open(f,'r') as fr:
            for line in fr:
                line = line.strip('\r\n')

                if line == '':
                    continue
                if line[-1] == ':':
                    continue
                if line[0] == ' ':
                    continue
                if line[0] == '=':
                    continue

                old_api.append(line)

    # Print preface
    print '''Signature::

    * Calling convention: WINAPI
    * Category: none

    '''

    # Read in new API hooks
    record = 0
    call = ''
    with open(new_fn,'r') as fr:
        for line in fr:
            line = line.strip('\r\n')

            if line == '':
                if record:
                    call += line + '\n'
                continue
            if line[-1] == ':':
                if record:
                    call += line + '\n'
                continue
            if line[0] == ' ':
                if record:
                    call += line + '\n'
                continue
            if line[0] == '=':
                if record:
                    call += line + '\n'
                continue

            # Print finished call
            sys.stdout.write(call)

            # If this new call is the old call
            if line in old_api:
                record = 1
                call = line + '\n'
            else:
                record = 0
                call = ''

if __name__ == '__main__':
    _main()
