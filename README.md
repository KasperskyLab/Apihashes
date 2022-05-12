## Apihashes v2 IDA plugin

Apihashes is an IDA plugin that allows to automatically identify and mark known hash values for API function names. 

The plugin is implemented as a hook that checks the operands of new instructions and data items, and uses a database of pre-calculated hashes.

The database is generated from a set of PE files using a script "make\_apihashesv2\_table.py". You can modify the script to add new hashing algorithms and non-standard DLLs.

## Installation

Copy the files apihashesv2.py, apihashesv2.bin (the database) and the directory apihashesv2\_search into the %IDADIR%/plugins directory. The plugin should be loaded automatically when IDA starts.

Dependencies: Python 3, pefile.

## Generating your own database

If needed, modify make\_apihashesv2\_table.py to add the new hashing algoritm. Add the function to the *hashers* list.

Run the script, providing the directories or filenames containing the target DLLs, for example the Windows "system32" directory.

```
python3 make_apihashesv2_table.py ...path_to_system32...
```

Processing will take some time, and as a result the script will generate a new file *apihashesv2.bin* in the current directory. Copy it to the %IDADIR%/plugins directory and reload IDA.

