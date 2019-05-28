from cryptography import x509
from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

INITIATOR_PASS ="402reset"
cert_file = open('sandbox.cer', 'r')
cert_data = cert_file.read()
cert_file.close()
cert = x509.load_pem_x509_certificate(str.encode(cert_data), default_backend())
public_key = cert.public_key()
cipher = public_key.encrypt(INITIATOR_PASS.encode('latin_1'), padding.PKCS1v15())
print(b64encode(cipher).decode('latin_1'))
