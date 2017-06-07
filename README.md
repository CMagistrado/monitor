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

