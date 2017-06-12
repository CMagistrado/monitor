# Figure out if there are any unmatched calls in monitor's debug output (in C:\ folder)

import sys
import re

def usage():
    print 'usage: python match.py monitor-debug-*.txt'
    sys.exit(1)

def _main():
    if len(sys.argv) != 2:
        usage()

    fn = sys.argv[1]

    matches = list()

    with open(fn,'r') as fr:
        for line in fr:
            line = line.strip('\r\n')

            m = re.match('Entered\s(.*)',line)
            if m:
                p = m.group(1)
                matches.append(p)
                continue

            m = re.match('Leaving\s(.*)',line)
            if m:
                p = m.group(1)
                matches.remove(p)
                continue

            m = re.match('Early\sleave\sof\s(.*)',line)
            if m:
                p = m.group(1)
                matches.remove(p)
                continue

    print 'Unmatched calls:'
    for m in matches:
        print '    ' + m

if __name__ == '__main__':
    _main()
