# Inferno Balls

### Decrypt.py
Decrypt.py can be used to decrypt the ciphertext and unlock the next Inferno Ball level.
It requires python 2.7, and the same dependencies relied on by as5-inferno.py (passlib, secretsharing), and reads two files, "shares.txt", containing the shares included in the JSON, with one share per line,
and cracked.txt, containing numbered passwords, one per line, in the format "NUMBER:CRACKEDPASSWORD", where NUMBER is the position of the
hash in the list of hashes in the level JSON, indexed at one, and CRACKEDPASSWORD is the cracked value of the hash.

### manager.py
Helps with basic file/level management. Functionality will be tuned and expanded during the duration of the project.

Args for InfernoManager(arg1,arg2)
- First arg - level file
- Second arg - level integer (for file naming)
  
#### Usage
Activate python shell by typing
```
python
```

You should see
```
>>>
```

Import and instanciate
```
from manager import InfernoManager
i = InfernoManager('inferno_ball_1.json',1)
```
Call funtions
```
i.export_hashes_to_files()
```
#### Available functions
All available functions are listed in manager.py script, under PUBLIC BLOCK

So far
```
export_hashes_to_files()
export_indexed_hashes()
get_ciphertext()
get_hashes()
get_shares()
```

### Level 1
Contained 5-8 character passwords derived from rockyou.txt, with a K of roughly 35 and N of 46
### Level 2
Seems to contain two four-letter words concatenated, with currently unknown K and N of 251.
### Level 3
Level 3 is made up of values from executing "pwgen -A 5". These are 5 letter words with at least one vowel, and exactly 1 digit
in either position 3, 4, or 5 (choo5, ohch3, aeph0, ya1ai)

