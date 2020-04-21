import sys
import argparse
import datetime
import uuid
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID

def my_fix_add_extension_cryptography(builder, extension, critical):
	from cryptography.x509.extensions import Extension, ExtensionType

	if not isinstance(extension, ExtensionType):
		raise TypeError("extension must be an ExtensionType")

	ext = Extension(extension.oid, critical, extension)
	return x509.CertificateBuilder(
		builder._issuer_name, builder._subject_name,
		builder._public_key, builder._serial_number, builder._not_valid_before,
		builder._not_valid_after, builder._extensions + [ext]
	)

def reload_key(keypem):
	return serialization.load_pem_private_key(
		data=keypem,
		password=None,
		backend=default_backend()
	)

def load_key(keyfile):
	key = b""
	with open(keyfile,"rb") as f:
		key = f.read()
	return reload_key(key)

def reload_cert(certpem):
	return x509.load_pem_x509_certificate(
		certpem,
		default_backend()
	)
	
def load_cert(certfile):
	cert = b""
	with open(certfile,"rb") as f:
		cert = f.read()
	return reload_cert(cert)

def write_output(txt, output=None):
	if output is None:
		print(txt.decode("utf-8"))
	else:
		with open(output,"wb") as f:
			f.write(txt)

def generate_rsa_key(bits=2048):
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

def def_certificate_subject():
	return x509.Name([
		x509.NameAttribute(
			NameOID.COUNTRY_NAME,
			input("Country Name (2 letter code) [AU] : ")
		),
		x509.NameAttribute(
			NameOID.STATE_OR_PROVINCE_NAME,
			input("State or Province Name (full name) [Some-State] : ")
		),
		x509.NameAttribute(
			NameOID.LOCALITY_NAME,
			input("Locality Name (eg, city) [] : ")
		),
		x509.NameAttribute(
			NameOID.ORGANIZATION_NAME,
			input("Organization Name (eg, company) [Internet Widgits Pty Ltd] : ")
		),
		x509.NameAttribute(
			NameOID.ORGANIZATIONAL_UNIT_NAME,
			input("Organizational Unit Name (eg, section) [] : ")
		),
		x509.NameAttribute(
			NameOID.COMMON_NAME,
			input("Common Name (e.g. server FQDN or YOUR name) [] : ")
		),
		x509.NameAttribute(
			NameOID.EMAIL_ADDRESS,
			input("Email Address [] : ")
		)
	])

def def_certificate_validity(builder, days):
	return builder.not_valid_before(
		datetime.datetime.today() - datetime.timedelta(1, 0, 0)
	).not_valid_after(
		datetime.datetime.today() + datetime.timedelta(days, 0, 0)
	)

def sign_and_return_certificate(builder, pubkey, sign_key, issuer, subject, caflag=True):
	builder = builder.serial_number(int(uuid.uuid4()))
	builder = builder.public_key(pubkey.public_key())
	builder = my_fix_add_extension_cryptography(
		builder,
		x509.BasicConstraints(
			ca=caflag,
			path_length=None
		),
		critical=True
	)
	builder = my_fix_add_extension_cryptography(
		builder,
		x509.SubjectKeyIdentifier(
			x509.SubjectKeyIdentifier.from_public_key(pubkey.public_key()).digest
		),
		critical=False
	)
	builder = my_fix_add_extension_cryptography(
		builder,
		x509.AuthorityKeyIdentifier(
			key_identifier=x509.SubjectKeyIdentifier.from_public_key(sign_key.public_key()).digest,
			authority_cert_issuer=None,
			authority_cert_serial_number=None
		),
		critical=False
	)
	
	certificate = None
	try :
		certificate = builder.sign(
			private_key=sign_key,
			algorithm=hashes.SHA256(),
			backend=default_backend()
		)
	except ValueError:
		certificate = builder.sign(
			private_key=sign_key,
			algorithm=None,
			backend=default_backend()
		)
	return certificate.public_bytes(
		encoding=serialization.Encoding.PEM
	)

def create_ca_root_certificate(key):
	builder = x509.CertificateBuilder()
	subject = def_certificate_subject()
	builder = builder.subject_name(subject)
	builder = builder.issuer_name(subject)
	builder = def_certificate_validity(builder, 365)
	return sign_and_return_certificate(builder, key, key, subject, subject)

def create_server_certificate(cakey, cacert, serv_key):
	builder = x509.CertificateBuilder()
	subject = def_certificate_subject()
	builder = builder.subject_name(subject)
	builder = builder.issuer_name(cacert.issuer)
	builder = def_certificate_validity(builder, 365)
	return sign_and_return_certificate(builder, serv_key, cakey, cacert.issuer, subject, False)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-k","--serverkey", help="Input target to process")
	parser.add_argument("-o","--output", help="Output file")
	parser.add_argument("-rsa","--rsa", action="store_true", help="Generate RSA key")
	parser.add_argument("-ed","--ed25519", action="store_true", help="Generate ed25519 key")
	parser.add_argument("-ca","--cakey", help="CA Key used to sign certificates")
	parser.add_argument("-b","--bits", type=int, help="Specify key length")
	parser.add_argument("-self","--self", action="store_true", help="Generate CA self signed certificate")
	parser.add_argument("-ce","--certificate", help="CA certificate to use to generate signed server certificate")
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
		cacertpem = create_ca_root_certificate(cakey)
		cacert = reload_cert(cacertpem)
		print("Server Certificate")
		scert = create_server_certificate(cakey, cacert, skey)
		write_output(cakeypem, "cakey.pem")
		write_output(skeypem, "skey.pem",)
		write_output(cacertpem, "cacert.pem")
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
			outtxt = create_ca_root_certificate(key)
	elif args.sign is not None:
		if args.privkey is not None and args.input is not None:
			cakey = load_key(args.privkey)
			skey = load_key(args.input)
			cacert = load_cert(args.sign)
			outtxt = create_certificate(cakey, cacert, skey)
	write_output(outtxt, file_output)
	
if __name__ == "__main__":
	main()
