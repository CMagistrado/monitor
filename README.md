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
$ python combine.py ./sigs/template/sigs.rst-full > ../sigs.rst 2>error
```

Any API calls not found will be printed in "error"

Then recompile monitor.

Explanation of functions: sigs/modeling/README.md

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
