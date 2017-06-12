monitor
=======

The new Cuckoo Monitor. [Click here for documentation][docs].
If at first it doesn't compile, just try a second time!

[docs]: http://cuckoo-monitor.readthedocs.org/en/latest/

## To automatically hook all API calls

Inside Developer Command Prompt:

```
$ cd get-symbols
$ python parse.py headers-folder dlls-folder
```

Put outputted sigs.rst file in monitor/sigs/ folder

```
$ cd ..
$ make
```

## Other tools

Inside Command Prompt:
```
# Printing out byte values of API functions
$ python debug.py

# Prints out hooked API functions used by monitor and sources
$ python scan.py

# Converts old signatures files to new file
$ python old_to_new.py

    # Example
    $ python old_to_new.py ../sigs-old/ ../sigs/sigs.rst-orig > ../sigs/sigs.rst
```

## Issues

**Cause `make` to error:**
  - GetConsoleFontSize
  - GetLargestConsoleWindowSize
```
error: aggregate value used where an integer was expected
         (uintptr_t) ret,
```

**Causes analyzer to error:**
  - FreeResource
  - GetCurrentThread
  - DeleteProcThreadAttributeList 
  - GetCurrentProcess
```
[analyzer] CRITICAL: Error creating function stub
```

**Causes analyzer to error:**
  - AddDllDirectory
  - RemoveDllDirectory
  - SetDefaultDllDirectories 
  - SystemTimeToTzSpecificLocalTimeEx
  - TzSpecificLocalTimeToSystemTimeEx
  - CopyContext
  - GetEnabledXStateFeatures
  - GetXStateFeaturesMask
  - InitializeContext
  - LocateXStateFeature
  - SetXStateFeaturesMask
```
[analyzer] DEBUG: Error resolving function
```
