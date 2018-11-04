# Inferno Balls

### Decrypt.py
Decrypt.py can be used to decrypt the ciphertext and unlock the next Inferno Ball level.
It requires python 2.7, and the same dependencies relied on by as5-inferno.py (passlib, secretsharing)

It requires the following files to be in the execution directory:
- shares.txt - taken from the corresponding LevelN folder, a line-separated list of shares for this level
- cracked.txt - a list of cracked passwords with the numerical position data from the json (XXX:PASSWORD)

It can then be executed as follows:
```
python decrypt.py levelN.json
```

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
### Level 4
Level 4 consisted of a wordlist generated from running cewl on scss.tcd.ie and tcd.ie
### Level 5
Level 5 consisted of hashed submitty usernames
### Level 6
Level 6 is the same as level 1 - rockyou.txt
### Level 7

