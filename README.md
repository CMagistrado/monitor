monitor
=======

The new Cuckoo Monitor. [Click here for documentation][docs].
If at first it doesn't compile, just try a second time!

[docs]: http://cuckoo-monitor.readthedocs.org/en/latest/

## To compile
Inside Linux shell:
```
$ cd ..
$ make
```

NOTE: This will compile this binary for Windows 7. To change,
change the Makefile's "\_WIN32\_WINNT" value to something
else: https://msdn.microsoft.com/en-us/library/6sehtctf.aspx

## To use old signatures (from original monitor)
Inside Linux shell:
```
$ cd ./sigs/
$ cp ./template/sigs.rst-old-stable sigs.rst
```

Then recompile monitor.

This sigs.rst-old-stable file is compiled from the
old signatures in ./sigs-old

## To generate signatures for API calls that can be used to model behavior
Inside Linux shell:
```
$ cd ./sigs/modeling
$ python combine.py ../template/sigs.rst-full > ../sigs.rst 2>error
```

Any API calls not found will be printed in "error"
Note that the "error" file already exists. This is the output
from the most recent run of combine.py and is kept for historic
purposes.

Then recompile monitor.

Functions hooked: [link](sigs/modeling)

Flags ignored/modified: [link](flags/README.md)

## To generate signatures for (most) API calls
Inside Developer Command Prompt (Windows):
```
$ cd get-symbols
$ python parse.py
```

Put the resulting sigs.rst file in ./sigs/template/sigs.rst-full

Note: Whilst this is a complete list of all API calls the parser
can see, it doesn't mean the monitor will compile. All objects and
data structures used by these calls may not be defined in this source.

In addition, this file is used by combine.py (mentioned above) to generate
the signature file for modeling behavior.

./get-symbols/parse.out is the output of running this script to retrieve
./sigs/template/sigs.rst-full. This is kept for historic reasons.

## Other tools
Inside Command Prompt (Windows):
```
# Printing out byte values of API functions (seeing where the hooking mechanism can fit)
$ python debug.py
```

Inside Linux shell:
```
$ cd ./get-symbols

# Prints out hooked API functions used by monitor and source
# Used to check that we're not hooking any function that the monitor uses
$ python scan.py

# Converts old signatures files to new file
# Used to put all old signatures into one file (./sigs/template/sigs.rst-old-stable)
$ python old_to_new.py

    # Example
    $ cd ./sigs
    $ python old_to_new.py ../sigs-old/ ./template/sigs.rst-full > ./template/sigs.rst-old-stable

# Finds mismatches of calls in monitor debug text file
# This debug file is outputted by monitor when compiled using `$ ./make_debug.sh`
# This script is used to see if any API call has been entered but not exited
$ python match.py

    # Example
    $ python match.py monitor-debug-1054.txt
```

## Issues
**Cause `make` to error:**
  - GetConsoleFontSize
  - GetLargestConsoleWindowSize
```
error: aggregate value used where an integer was expected
         (uintptr_t) ret,
```

**Missing types**
Had to add "#include <ws2ipdef.h>" to "/usr/share/mingw-w64/include/netioapi.h"
because of missing SOCKADDR\_INET definition.

/usr/share/mingw-w64/include/cryptxml.h
    - error: variable or field declared void
    - Change it to "void \*pvPaddingInfo" on line 83
    - Change it to "void \*pvExtraInfo" on line 84

    - Commented out "CryptXmlDllVerifySignature" because could not find definition
      of HCRYPTXML_PROV
    - Commented out CRYPT_XML_CRYPTOGRAPHIC_INTERFACE
    - Commented out CryptXmlDllGetInterface

    - Had to move "CRYPT_XML_KEY_VALUE" to above "CRYPT_XML_KEY_INFO_ITEM" and past
      a few variables because it wasn't ordered properly.

/usr/share/mingw-w64/include/windns.h
    - Added datatypes and functions (see comment "// evan:")
    - E.g., I added DNS_PROXY_INFORMATION_TYPE data type (and others) because "DnsGetProxyInformation()"
      required it.

/usr/share/mingw-w64/include/wininet.h
    - Commented out "#define HTTP\_VERSION \_\_MINGW\_NAME\_AW(HTTP\_VERSION)" because of
      conflicting type (HTTP_VERSION) in http.h

/usr/share/mingw-w64/include/http.h
    - Added ";" at end of line 459 (HTTP_PROPERTY_FLAGS)
    - Added HTTP_LOG_DATA data type
    - Added HTTP_SERVICE_CONFIG_TIMEOUT_PARAM data type
    - Added HTTP_URL_GROUP_ID and HTTP_SERVER_SESSION_ID data types
    - Copied contents of HTTP_REQUEST_V1 directly into HTTP_REQUEST_V2 because the Windows
      compiler handles this weird case. GCC does not.
      - Did same with HTTP_RESPONSE_V1 and HTTP_RESPONSE_V2
