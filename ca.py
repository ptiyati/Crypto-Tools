import sys
import argparse
import datetime
import uuid
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID

def load_key(keyfile):
	key = ""
	with open(keyfile,"rb") as f:
		key = f.read()
	return serialization.load_pem_private_key(
		data=key,
		password=None,
		backend=default_backend()
	)

def reload_key(keypem):
	return serialization.load_pem_private_key(
		data=keypem,
		password=None,
		backend=default_backend()
	)
	
def write_output(txt, output=None):
	if output is None:
		print(txt.decode("utf-8"))
	else:
		with open(output,"wb") as f:
			f.write(txt)

def generate_rsa_key(bits):
	key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=bits,
		backend=default_backend()
	)
	keypem = key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)
	return keypem

def generate_ed25519_key():
	key = ed25519.Ed25519PrivateKey.generate()
	keypem = key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)
	return keypem

def create_certificate(cakey, skey):
	builder = x509.CertificateBuilder()
	issuer_name = input("COMMON NAME : ")
	builder = builder.subject_name(
		x509.Name([
			x509.NameAttribute(
				NameOID.COMMON_NAME,
				issuer_name
			),
			x509.NameAttribute(
				NameOID.ORGANIZATION_NAME,
				input("ORGANIZATION NAME : ")
			),
			x509.NameAttribute(
				NameOID.ORGANIZATIONAL_UNIT_NAME,
				input("ORGANIZATIONAL UNIT NAME : ")
			),
		])
	)
	if cakey!=skey:
		issuer_name = input("ISSUER NAME : ")
	builder = builder.issuer_name(
		x509.Name([
			x509.NameAttribute(
				NameOID.COMMON_NAME,
				issuer_name
			)
		])
	)
	builder = builder.not_valid_before(
		datetime.datetime.today() - datetime.timedelta(1, 0, 0)
	)
	builder = builder.not_valid_after(
		datetime.datetime.today() + datetime.timedelta(365, 0, 0)
	)
	builder = builder.serial_number(int(uuid.uuid4()))
	builder = builder.public_key(skey.public_key())
	buider = builder.add_extension(
		x509.BasicConstraints(
			ca=True,
			path_length=None
		),
		critical=True
	)
	try :
		certificate = builder.sign(
			private_key=cakey,
			algorithm=hashes.SHA256(),
			backend=default_backend()
		)
	except ValueError:
		certificate = builder.sign(
			private_key=cakey,
			algorithm=None,
			backend=default_backend()
		)
	return certificate.public_bytes(
		encoding=serialization.Encoding.PEM
	)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-k","--serverkey", help="Input target to process")
	parser.add_argument("-o","--output", help="Output file")
	parser.add_argument("-rsa","--rsa", action="store_true", help="Generate RSA key")
	parser.add_argument("-ed","--ed25519", action="store_true", help="Generate ed25519 key")
	parser.add_argument("-ca","--cakey", help="CA Key used to sign certificates")
	parser.add_argument("-b","--bits", type=int, help="Specify key length")
	parser.add_argument("-self","--self", action="store_true", help="Generate CA self signed certificate")
	parser.add_argument("-sign","--sign", action="store_true", help="Generate server certificate signed with CA certificate")
	parser.add_argument("-a","--all", action="store_true", help="Generate CA and server keys and certificates")
	args = parser.parse_args()
	file_output = args.output
	outtxt = b""
	if args.all:
		cakeypem = b""
		skeypem = b""
		cakey = None
		skey = None
		cacert = b""
		scert = b""
		if args.ed25519:
			cakeypem = generate_ed25519_key()
			skeypem = generate_ed25519_key()
		else:
			bits = args.bits or 2048
			cakeypem = generate_rsa_key(bits)
			skeypem = generate_rsa_key(bits)
		cakey = reload_key(cakeypem)
		skey = reload_key(skeypem)
		print("CA Certificate")
		cacert = create_certificate(cakey, cakey)
		print("Server Certificate")
		scert = create_certificate(cakey, skey)
		write_output(cakeypem, "cakey.pem")
		write_output(skeypem, "skey.pem",)
		write_output(cacert, "cacert.pem")
		write_output(scert, "scert.pem",)
	elif args.rsa:
		if args.bits is not None:
			outtxt = generate_rsa_key(args.bits)
		else:
			outtxt = generate_rsa_key(2048)
	elif args.ed25519:
		outtxt = generate_ed25519_key()
	elif args.self:
		if args.privkey is not None:
			key = load_key(args.privkey)
			outtxt = create_certificate(key, key)
	elif args.sign:
		if args.privkey is not None and args.input is not None:
			cakey = load_key(args.privkey)
			skey = load_key(args.input)
			outtxt = create_certificate(cakey, skey)
	write_output(outtxt, file_output)
	
if __name__ == "__main__":
	main()
