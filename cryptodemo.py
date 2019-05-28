from Crypto.PublicKey import RSA
key = RSA.generate(2048)
f = open('mykey','wb')
f.write(key.exportKey())
f.close()
