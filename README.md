# Inferno Balls

### Decrypt.py
Decrypt.py can be used to decrypt the ciphertext and unlock the next Inferno Ball level.
It requires python 2.7, and the same dependencies relied on by as5-inferno.py (passlib, secretsharing), and reads two files, "shares.txt", containing the shares included in the JSON, with one share per line,
and cracked.txt, containing numbered passwords, one per line, in the format "NUMBER:CRACKEDPASSWORD", where NUMBER is the position of the
hash in the list of hashes in the level JSON, indexed at one, and CRACKEDPASSWORD is the cracked value of the hash.

### Level 1
Contained 5-8 character passwords derived from rockyou.txt, with a K of roughly 35 and N of 46
### Level 2
Seems to contain two four-letter words concatenated, with currently unknown K and N of 251.

