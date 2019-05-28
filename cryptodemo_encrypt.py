from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
f = open('mykey','r')
clientkey = RSA.importKey(f.read())
#Error NotImplementedError: Use module Crypto.Cipher.PKCS1_OAEP instead
cipher = PKCS1_v1_5.new(clientkey.publickey())
encdata = cipher.encrypt("hello python".encode())
d = open('encrypted', 'wb')
d.write(encdata)
d.close()
