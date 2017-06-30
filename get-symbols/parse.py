import sys
import os
import re

# Parse return value for content
def parse_rv(param):
    # Ignore comments
    param = re.sub('/.*','',param)

    # Ignore whitespace
    param = re.sub('^\s+','',param)
    param = re.sub('\s+$','',param)

    # Ignore (...) before parameter
    param = re.sub('^\(.*\)\s+','',param)

    # Ignore annotations
    param = re.sub('_\w+_\(.*\)\s*','',param)
    param = re.sub('_\w+_\s+','',param)
    param = re.sub('\s+OPTIONAL.*','',param)
    param = re.sub('OPTIONAL\s+','',param)
    param = re.sub('^CONST\s+','const ',param)
    param = re.sub('^VOID\s+','void ',param)
    param = re.sub('^__callback\s+','',param)
    param = re.sub('^__drv_aliasesMem\s+','',param)

    # Ignore (...)
    param = re.sub('\(.*\)\s*','',param)

    # Consolidate whitespace
    param = re.sub('\s+',' ',param)

    # If void, uncapitalize it
    if param == 'VOID':
        param = 'void'

    # Remove space after * if one exists
    param = re.sub('\*\s+','*',param)

    # Add space before * if one doesn't exist
    param = re.sub('(\w+)\*',r'\1 *',param)

    return param

# Parse parameter for content
def parse_param(param):
    # Ignore comments
    param = re.sub('/.*','',param)

    # Ignore whitespace
    param = re.sub('^\s+','',param)
    param = re.sub('\s+$','',param)

    if len(param) == 0:
        return ''

    # Remove comma if it exists
    if param[-1] == ',':
        param = ''.join(param[:-1])

    # Remove ); if it exists
    if len(param) >= 2:
        if ''.join(param[-2:]) == ');':
            param = ''.join(param[:-2])

    # Ignore (...) before parameter
    param = re.sub('^\(.*\)\s+','',param)

    # Ignore annotations
    param = re.sub('_\w+\(.*\)\s*','',param)
    param = re.sub('_\w+_\(.*\)\s*','',param)
    param = re.sub('_\w+_\(.*\)\s*','',param)
    param = re.sub('_\w+_\s+','',param)
    param = re.sub('IN\s+','',param)
    param = re.sub('OUT\s+','',param)
    param = re.sub('\s+OPTIONAL.*','',param)
    param = re.sub('OPTIONAL\s+','',param)
    param = re.sub('^CONST\s+','const ',param)
    param = re.sub('^VOID\s+','void ',param)
    param = re.sub('^__callback\s+','',param)
    param = re.sub('^__drv_aliasesMem\s+','',param)

    # Ignore (...)
    param = re.sub('\(.*\)\s*','',param)

    # Consolidate whitespace
    param = re.sub('\s+',' ',param)

    # If void, ignore this parameter
    if param == 'VOID':
        param = ''

    # Remove space after * if one exists
    param = re.sub('\*\s+','*',param)

    # Add space before * if one doesn't exist
    param = re.sub('(\w+)\*',r'\1 *',param)

    # If "void const", change to "void"
    param = re.sub('void const ','void ',param)

    # Remove "FAR".
    param = re.sub('FAR ','',param)

    # TODO Cases we can't handle yet
    # Variable parameters
    if '...' in param:
        return False
    # Parameter with just one type (no name)
    if (len(param) > 0) and (' ' not in param):
        return False

    return param

# Retrieves the rest of this API call and prints it to file
def get_api(out,fd,apicall_to_dll,written_names,rv,name):
    param = list()

    # Prepare API call in correct format
    while True:
        # Read line
        line = fd.readline()
        if not line:
            break

        line = line.strip('\r\n')

        if not useful(line):
            continue

        # If rv hasn't been filled in yet
        if rv == '':
            # If return value has some weird _blah_() stuff next to it
            m = re.match('^\s*_\w+_\(.*\)\s*(\w+)$',line)
            if m:
                rv = m.group(1)
            else:
                rv = line

        # If name hasn't been filled in yet
        elif name == '':
            # If this looks like a function
            m = re.match('^\s*(\w+)\s*\($',line)
            if m:
                name = m.group(1)

            m = re.match('^\s*(\w+)\s*\n\($',line)
            if m:
                name = m.group(1)

            # API call name and parameters all on one line
            m = re.match('^\s*(\w+)\s*\((.*)\);$',line)
            if m:
                name = m.group(1)
                for p in m.group(2).split(','):
                    # Get parameters
                    newp = parse_param(p)

                    # Can't handle this function
                    if newp == False:
                        print 'Can\'t handle {0} yet'.format(name)
                        return

                    # Add parameter to list
                    if newp != '':
                        param.append(newp)

        # If parameters haven't been filled in yet
        elif not param:
            while True:
                line = line.strip('\r\n')

                # TODO: handle this case
                # Can't handle #'s within functions
                if '#' in line:
                    print 'Can\t handle {0} yet'.format(name)
                    return

                if not useful(line):
                    line = fd.readline()
                    # If this is the end of the file
                    if not line:
                        break

                    continue

                # Get parameters
                newp = parse_param(line)

                # Can't handle this function
                if newp == False:
                    print 'Can\'t handle {0} yet'.format(name)
                    return

                # Add parameter to list
                if newp != '':
                    param.append(newp)

                # If this was the last parameter
                if ');' in line:
                    break

                line = fd.readline()
                # If this is the end of the file
                if not line:
                    break

        # Are we done with this API call?
        if ');' in line:
            break

        # If this is the end of the file
        if not line:
            break

    # Print out to signatures file
    if rv != '' and name != '':
        # If name has already been written
        if name in written_names:
            return

        # If name not in library
        if name not in apicall_to_dll:
            print '{0} not found in DLL'.format(name)
            return

        # Pick from list of potential libraries
        library = ''
        for l in apicall_to_dll[name]:
            # No dashes in our library
            if '-' in l:
                continue
            # No uppercase letters in our library
            if any(c.isupper() for c in l):
                continue

            library = l 

        if not len(library):
            print '{0} no library name'.format(name)
            return

        # Add name to written list
        written_names.add(name)

        with open(out,'a') as fa:
            fa.write('{0}\n'.format(name))
            fa.write('='*len(name))
            fa.write('\n\n')

            fa.write('Signature::\n\n')
            fa.write('    * Library: {0}\n'.format(library))
            fa.write('    * Return value: {0}\n'.format(parse_rv(rv)))

            # Write out parameters
            if len(param) > 0:
                fa.write('\n')
                fa.write('Parameters::\n\n')
                for p in param:
                    fa.write('    ** {0}\n'.format(p))

            fa.write('\n\n')

# Determines if line is useful or not
def useful(line):
    # If no content is on line
    if not line:
        return False

    # If this is a comment
    if line[0] == '/':
        return False

    # If this is a # define
    if line[0] == '#':
        return False

    # If this is a _Blah_() line
    m = re.match('^\s*_\w+_\(.*\)\s*$',line)
    if m:
        return False

    # If this is a _Blah_ line
    m = re.match('^_\w+_$',line)
    if m:
        return False

    # If this is a __Blah line
    m = re.match('^\s*__\w+.*$',line)
    if m:
        return False

    return True

# Retrieves all *.dll files within this folder (recursively)
def get_dll_files(path):
    for root, dirs, files in os.walk(path):
        for f in files:
            if '.dll' == f[-4:]:
                yield os.path.join(root,f)

# Retrieves all *.h files within this folder (recursively)
def get_header_files(path):
    for root, dirs, files in os.walk(path):
        for f in files:
            if '.h' == f[-2:]:
                yield os.path.join(root,f)

def usage():
    print 'usage: python parse.py path\\to\\headers\\ path\\to\\dlls'
    print ''
    print 'example: python parse.py C:\\Program Files\\Windows Kits\\8.1\\Include\\um C:\\Windows\\System32'
    sys.exit(1)

def _main():
    if len(sys.argv) != 3:
        usage()

    header_folder = sys.argv[1]
    dll_folder = sys.argv[2]

    # File we'll put our signatures in
    sigs_file = 'sigs.rst'

    with open(sigs_file,'w') as fw:
        fw.write('Signature::\n\n')
        fw.write('    * Calling convention: WINAPI\n')
        fw.write('    * Category: none\n\n\n')

    # If neither of these folders exist, error
    if (not os.path.exists(header_folder)) or (not os.path.exists(dll_folder)):
        print 'Error. Folder does not exist'
        usage()

    # Get all files we're interested in
    header_fns = get_header_files(header_folder)

    # Get all files we're interested in
    dll_fns = get_dll_files(dll_folder)

    # Dictionary of mappings between api calls and dll files
    apicall_to_dll = dict()

    # Extract header file functions belonging to each DLL file
    #TODO evan: debugging
#   dll_fns = ['C:\\Windows\\System32\\winhttp.dll']
    for fn in dll_fns:
#       print 'Reading {0}'.format(fn)

        # Get export symbols from file
        out = os.popen('dumpbin /EXPORTS {0}'.format(fn)).read()

        # Record symbols which match entries in DLL files
        flag = 0
        for line in out.split('\n'):
            # End of section we care about
            m = re.match('\s*Summary',line)
            if m:
                flag = 0

            # Section we care about
            if flag:
                symbol = ''

                m = re.match('\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+).*',line)
                if m:
                    symbol = str(m.group(4))

                else:
                    m = re.match('\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+).*',line)
                    if m:
                        symbol = str(m.group(3))

                if symbol != '':
                    dll_name = os.path.basename(fn)[:-4]

                    if symbol not in apicall_to_dll:
                        apicall_to_dll[symbol] = list()

                    apicall_to_dll[symbol].append(dll_name)

            # Start of section we care about
            m = re.match('\s*ordinal\s*hint\s*RVA\s*name.*',line)
            if m:
                flag = 1

    #NOTE - debugging
#   for symbol in apicall_to_dll:
#       print '{0}: {1}'.format(symbol, str(apicall_to_dll[symbol]))

    written_names = set()

    # Extract declarations from each header file
    #TODO evan: debugging
#   header_fns = ['C:\\Program Files\\Windows Kits\\8.1\\Include\\um\\winhttp.h']
    for fn in header_fns:
#       print 'Reading {0}'.format(fn)
        if 'winhttp.h' in fn:
            print 'Can\'t handle winhttp.h'
            continue

        # Open file for reading
        fd = open(fn,'r')
        line = fd.readline()
        previousline = ''

        # Read file
        while True:
            # Strip out the newlines
            line = line.strip('\r\n')

            # If this isn't a useful file, read next line
            if not useful(line):
                line = fd.readline()
                # If this is the end of the file
                if not line:
                    break

                continue

            # Parse for start of API call
            m = re.match('^\w+API$',line)
            if m:
                rv = ''
                name = ''

                # Like in wininet.h
                if line == 'BOOLAPI':
                    rv = 'BOOL'

                # If the API call wasn't prefixed (e.g., compressapi.h)
                elif line == 'WINAPI' or line == 'SDBAPI' or line == 'IMAGEAPI' or line == 'WSAAPI' or line == 'WSPAPI':
                    rv = previousline

                # Get rest of API call
                get_api(sigs_file,fd,apicall_to_dll,written_names,rv,name)

            # Keep track of previous line
            previousline = line

            # Read next line
            line = fd.readline()
            if not line:
                break

        # Close file
        fd.close()

if __name__ == '__main__':
    _main()
