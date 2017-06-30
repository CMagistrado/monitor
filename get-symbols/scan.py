# Determines if monitor uses any Windows API calls that it itself hooks
import sys
import os

from subprocess import check_output, CalledProcessError

def get_rst_files(path):
    #key = '.rst-orig'
    key = '.rst'

    for root, dirs, files in os.walk(path):
        for f in files:
            if key == f[-len(key):]:
                yield os.path.join(root,f)

def usage():
    print 'usage: python scan.py sigs-folder'
    sys.exit(1)

def _main():
    if len(sys.argv) != 2:
        usage()

    # Read in APIs hooked
    api = list()
    fns = get_rst_files(sys.argv[1])
    for f in fns:
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

                api.append(line)

    # See if monitor uses APIs in source
    for a in api:
        try:
            out = check_output('grep -rI "{0}(" ../src/*.c'.format(a), shell=True)
            print out

            out = check_output('grep -rI "{0}(" ../bin/*.c'.format(a), shell=True)
            print out
        except CalledProcessError:
            pass

if __name__ == '__main__':
    _main()
