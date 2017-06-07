import sys
import os
import re

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
    for fn in header_fns:
#       print 'Reading {0}'.format(fn)

        flag = 0
        rv = ''
        name = ''
        params = list()
        separate = 0

        with open(fn,'r') as fr:
            for line in fr:
                line = line.strip('\n')

                # End of section we care about
                m = re.match('.*\);',line)
                if m:
                    # If no name was recorded, ignore it
                    if name == '':
                        continue

                    p = ''

                    # Do we have to ignore the '_IN_', etc. stuff?
                    m = re.match('\s*_[A-Za-z]+_\s(.*)\);',line)
                    m2 = re.match('\s*_[A-Za-z]+_\(.*\)\s(.*)\);',line)
                    m3 = re.match('\s*([A-Za-z]+)\);',line)
                    if m:
                        p = m.group(1)
                    elif m2:
                        p = m2.group(1)
                    elif m3:
                        p = m3.group(1)

                    # Append last parameter
                    if p != '':
                        params.append(p)

                    # Don't declare duplicate functions
                    if name in written_names:
                        # Clear out information, we're done with this call declaration
                        flag = 0
                        rv = ''
                        name = ''
                        del params[:]
                        separate = 0
                        continue

                    # Keep track of what fuctions we've written
                    written_names.add(name)

                    # Write API declaration to file
                    with open(sigs_file,'a') as fa:
                        fa.write('{0}\n'.format(name))
                        fa.write('='*len(name))
                        fa.write('\n')
                        fa.write('\n')

                        fa.write('Signature::\n\n')

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
                        
                        fa.write('    * Library: {0}\n'.format(library))


                        # Replace VOID with void
                        if rv == 'VOID':
                            fa.write('    * Return value: void\n')
                        else:
                            fa.write('    * Return value: {0}\n'.format(rv))

                        fa.write('\n')

                        # Don't print out parameters if only parameter is void
                        if len(params) == 1:
                            if params[0].split(' ')[-1] == 'VOID':
                                fa.write('\n')

                                # Clear out information, we're done with this call declaration
                                flag = 0
                                rv = ''
                                name = ''
                                del params[:]
                                separate = 0

                                continue

                        fa.write('Parameters::\n\n')
                        for p in params:
                            # Remove space after * if one exists
                            p = re.sub('\*\s+','*',p)

                            # Add space before * if one doesn't exist
                            p = re.sub('([A-Za-z0-9_]+)\*',r'\1 *',p)

                            # Replace VOID with void
                            p = re.sub('^VOID','void',p)

                            fa.write('    ** {0}\n'.format(' '.join(p.split())))
                        fa.write('\n')
                        fa.write('\n')


                    # Clear out information, we're done with this call declaration
                    flag = 0
                    rv = ''
                    name = ''
                    del params[:]
                    separate = 0

                # Section we care about
                if flag:
                    # First we'll see the return value type
                    if rv == '':
                        # Sometimes Windows puts __When__() crap before the return value data type
                        if '_' != line.lstrip(' ')[0]:
                            rv = line
                        continue

                    # Next we'll see the API call name and parameters
                    elif name == '':
                        if line == 'WINAPI' or line == 'APIENTRY':
                            continue

                        # Unfortunately Windows varies this next part quite a bit.
                        # Some declarations' parameters and names are separated by newlines,
                        # and some aren't.

                        # Just the name
                        m = re.match('^([A-Za-z0-9_]+)\s*\($',line)
                        if m:
                            name = m.group(1)
                            separate = 1
                        else:
                            # The entire thing on one line
                            m = re.match('^([A-Za-z0-9_]+)\s*\((.*)\);$',line)
                            if m:
                                name = m.group(1)
                                params.append(m.group(2))
                                separate = 0

                        if name == '':
                            continue

                        # Make sure this call is in a dll file
                        if name not in apicall_to_dll:
                            print '{0} not in a DLL file.'.format(name)
                            flag = 0
                            rv = ''
                            name = ''

                        continue

                    if separate:
                        # If "parameter" has ) at the end, it's probably because of _When_()
                        if line[-1] == ')':
                            continue

                        # Do we have to ignore the '_IN_', etc. stuff?
                        m = re.match('.*_[A-Za-z]+_\s(.*)',line)
                        if m:
                            p = m.group(1)
                        else:
                            # Do we have to ignore the '_Out_writes_to_opt_(...)', etc. stuff?
                            m = re.match('.*_[A-Za-z]+_\(.*\)\s(.*)',line)
                            if m:
                                p = m.group(1)
                            else:
                                p = line


                        # Do we have to ignore _When_() stuff??
                        p = re.sub('_When_\(.*\)\s','',p)

                        # Do we have to ignore _Deref_out_range_() stuff??
                        p = re.sub('_Deref_out_range_\(.*\)\s','',p)

                        # Do we have to ignore comments?
                        p = re.sub('\s//.*','',p)

                        # Do we have to ignore (...) before the parameter?
                        p = re.sub('\(.*\)\s','',p)

                        # Do we have to ignore CONST?
                        p = re.sub('CONST\s','',p)

                        # Do we have to ignore __callback?
                        p = re.sub('__callback\s','',p)

                        # Do we have to ignore __drv_aliasesMem?
                        p = re.sub('__drv_aliasesMem\s','',p)

                        # If parameter has a comma at the end, ignore it
                        if p[-1] == ',':
                            params.append(p[:-1])
                        # Else it's a normal line
                        else:
                            params.append(p)


                # Start of section we care about
                m = re.match('WINBASEAPI',line)
                if m:
                    flag = 1

if __name__ == '__main__':
    _main()
