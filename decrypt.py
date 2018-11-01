#!/usr/bin/python

import secretsharing as sss

# for JSON output
import jsonpickle # install via  "$ sudo pip install -U jsonpickle"

# for hashing passwords
from hashlib import sha256

# needed for these: sudo -H pip install passlib argon2_cffi
from passlib.hash import pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt

# for non-security sensitive random numbers
from random import randrange

# for encrypting you need: sudo -H pip install pycrypto
import base64
from Crypto.Cipher import AES
from Crypto import Random

# our cs7ns1-specific functions for shamir-like sharing

def pxor(pwd,share):
    '''
      XOR a hashed password into a Shamir-share

      1st few chars of share are index, then "-" then hexdigits
      we'll return the same index, then "-" then xor(hexdigits,sha256(pwd))
      we truncate the sha256(pwd) to if the hexdigits are shorter
      we left pad the sha256(pwd) with zeros if the hexdigits are longer
      we left pad the output with zeros to the full length we xor'd
    '''
    words=share.split("-")
    hexshare=words[1]
    slen=len(hexshare)
    hashpwd=sha256(pwd).hexdigest()
    hlen=len(hashpwd)
    outlen=0
    if slen<hlen:
        outlen=slen
        hashpwd=hashpwd[0:outlen]
    elif slen>hlen:
        outlen=slen
        hashpwd=hashpwd.zfill(outlen)
    else:
        outlen=hlen
    xorvalue=int(hexshare, 16) ^ int(hashpwd, 16) # convert to integers and xor 
    paddedresult='{:x}'.format(xorvalue)          # convert back to hex
    paddedresult=paddedresult.zfill(outlen)       # pad left
    result=words[0]+"-"+paddedresult              # put index back
    return result

def newsecret(numbytes):
    '''
        let's get a number of pseudo-random bytes, as a hex string
    '''
    binsecret=open("/dev/urandom", "rb").read(numbytes)
    secret=binsecret.encode('hex')
    return secret

def pwds_to_shares(pwds,k,numbytes):
    '''
        Give a set of n passwords, and a threshold (k) generate a set
        of Shamir-like 'public' shares for those.

        We do this by picking a random secret, generating a set of
        Shamir-shares for that, then XORing a hashed password with 
        each share.  Given the set of 'public' shares and k of the
        passwords, one can re-construct the secret.

        Note:  **There are no security guarantees for this**
        This is just done for a student programming exercise, and
        is not for real use. With guessable passwords, the secret 
        can be re-constructed!

    '''
    n=len(pwds) # we're in k-of-n mode...
    secret=newsecret(numbytes) # generate random secret
    shares=sss.SecretSharer.split_secret(secret,k,n) # split secret
    diffs=[] # diff the passwords and shares
    for i in range(0,n):
        diffs.append(pxor(pwds[i],shares[i]))
    return diffs

def pwds_shares_to_secret(kpwds,kinds,diffs):
    '''
        take k passwords, indices of those, and the "public" shares and 
        recover shamir secret
    '''
    shares=[]
    for i in range(0,len(kpwds)):
        shares.append(pxor(kpwds[i],diffs[kinds[i]-1]))
    secret=sss.SecretSharer.recover_secret(shares)
    return secret

# password hashing primitives

def newhash(p):
    '''
        Randomly pick a hash function and apply it
    '''
    # hashes supported
    hashalgs=[pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt]
    halg=randrange(0,len(hashalgs))
    hash=hashalgs[halg].hash(p)
    return hash

# encrypt wrapper

# modified from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def decrypt(enc, password):
    private_key = password
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

def encrypt(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

# main code...

# magic JSON incantation (I forget why, might not even be needed here:-)
jsonpickle.set_encoder_options('json', sort_keys=True, indent=2)
jsonpickle.set_encoder_options('simplejson', sort_keys=True, indent=2)

try:
    secrets = []
    kinds = []
    lpwds = [] 
    f = open('shares.txt', 'r')
    shares = f.readlines()
    f.close()
    with open("cracked.txt", "r") as f:
        for line in f:
            newline = line.rstrip()
            kinds.append(int(newline.split(':')[0]))
            lpwds.append(newline.split(':')[1])
    lthresh = len(lpwds)
    levelsecret=pwds_shares_to_secret(lpwds,kinds,shares)
    secrets.append(levelsecret)
    csname="output.secrets"
    path=os.path.join(tmpdir,csname)
    cryptpath="crypto.txt"
    with open(cryptpath, "r") as crypto:
        encrypted = crypto.read()
        print decrypt(encrypted, levelsecret.zfill(32).decode('hex'))
    crypto.close()
        
    with open(path,"w") as tmpf:
        for sec in secrets:
            tmpf.write(sec+"\n")
    tmpf.close()
    shutil.move(path,destdir+"/"+csname)
except Exception as e:
    print >>sys.stderr, "Exception doing: " + args.username + " " + str(e)
    sys.exit(5)
finally:
    # clean up
    os.umask(saved_umask)
    shutil.rmtree(tmpdir,ignore_errors=True)

# success return, we're all done!
sys.exit(0)
