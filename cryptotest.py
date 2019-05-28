# from cryptography import x509
# from base64 import b64encode
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa
# from Crypto.Cipher import PKCS1_v1_5
# from Crypto.PublicKey import RSA
#
# INITIATOR_PASS ="402reset"
# cert_file = open('cert.cer', 'r')
# cert_data = cert_file.read()
# cert_file.close()
# cert = x509.load_pem_x509_certificate(str.encode(cert_data), default_backend())
# public_key = cert.public_key()
# pkcs = PKCS1_v1_5.new(public_key)
# cipher = pkcs.encrypt(INITIATOR_PASS.encode('latin_1'))
# print(b64encode(cipher.decode('latin_1')))

# Using https://pysheeet.readthedocs.io/en/latest/notes/python-security.html#simple-rsa-encrypt-via-pem-file
from base64 import b64encode
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import pem

INITIATOR_PASS ="402reset"
# cert_file = open('cert.cer', 'r')
# cert_data = cert_file.read()
# cert_file.close()
# cert = x509.load_pem_x509_certificate(str.encode(cert_data), default_backend())
cert = pem.parse_file('sandbox.cer')
# public_key = pem.RSAPublicKey(cert[0].as_text())
public_key = RSA.importKey(cert[0].as_text())
import pdb; pdb.set_trace()
cipher = PKCS1_v1_5.new(public_key)
ciphertext = cipher.encrypt(INITIATOR_PASS.encode('latin_1'))
print(b64encode(ciphertext).decode('latin_1'))
