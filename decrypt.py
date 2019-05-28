from Crypto.Hash import SHA
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
f = open('mykey','r')
encdata = open('encrypted', 'r')
import pdb; pdb.set_trace()
dsize = SHA.digest_size
sentinel = Random.new().read(15+dsize)
clientkey = RSA.importKey(f.read())
cipher = PKCS1_v1_5.new(clientkey.publickey())
t=cipher.decrypt(encdata, sentinel)
print (t)
