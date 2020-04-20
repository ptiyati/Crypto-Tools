import sys
import argparse
from Crypto.PublicKey import RSA


def write_output(txt, path=None):
	if output is None:
		print(keystr)
	with open(output,"w") as f:
		f.write()
	

def generate_rsa_key(bits):
	key = RSA.generate(bits)
	keystr = key.export_key('PEM')

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("input", help="Input target to process")
	parser.add_argument("-o","output", help="Output file")
	parser.add_argument("-r","rsa", help="Generate RSA key")
	parser.add_argument("-b","bits", type=int, help="Specify key length")
	parser.add_argument("-s","self", help="Generate CA self signed certificate")
	parser.add_argument("-c","certificate", action="store_true", help="Generate server certificate signed with CA certificate")
	if parser.rsa is not None:
		key = ""
		if parser.bits is not None:
			key = generate_rsa_key(parser.bits, parser.output)
		else:
			key = generate_rsa_key(2048)
		write_output(key, parser.output)
	elif parser.certificate is not None:
		
		
	
if __name__ == "__main__":
	main()
