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

## Issues

**Cause `make` to error:**
  - GetConsoleFontSize
  - GetLargestConsoleWindowSize
```
error: aggregate value used where an integer was expected
         (uintptr_t) ret,
```

**Causes analyzer to error:**
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
