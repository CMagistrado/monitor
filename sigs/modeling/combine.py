import sys
import os

def usage():
    print 'usage: python combine.py'
    sys.exit(1)

def _main():
    if len(sys.argv) != 1:
        usage()

if __name__ == '__main__':
    _main()
