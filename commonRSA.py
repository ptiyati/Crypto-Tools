#!/usr/bin/env python3

import sys
import binascii
import base64
from Crypto.PublicKey import RSA

def usage():
	print('Usage : ')
	print('\t'+sys.argv[0]+' file')
	print('\t'+sys.argv[0]+' raw')

def egcd(a,b):
	if a==0:
		return (b,0,1)
	g, y, x = egcd(b%a,a)
	return (g,x-(b//a)*y,y)

def modinv(a,m):
	g, x, y = egcd(a, m)
	if g!=1:
		raise Exception('No Modular Inverse')
	return x%m

def pow_mod(x,y,z):
	"x^y %z"
	if y<0:
		x=modinv(x,z)
		y=-y
	number=1
	while y:
		if y & 1:
			number=number*x % z
		y >>= 1
		x = x * x % z
	return number

def get_input_stdin():
	print('Enter the RSA Modulus :',end='\t')
	try :
		N=int(input(),16)
	except:
		print('Bad Input on firstmodulus')
		N=None
	print('Enter the first public RSA exponent :',end='\t')
	try :
		e1=int(input(),16)
	except:
		print('Bad Input on second modulus')
		e1=None
	print('Enter first Ciphertext :',end='\t')
	try :
		c1=int(input(),16)
	except:
		print('Bad Input on first ciphertext')
		c1=None
	print('Enter the second public RSA exponent :',end='\t')
	try :
		e2=int(input(),16)
	except:
		print('Bad Input on third modulus')
		e2=None
	print('Enter second Ciphertext :',end='\t')
	try :
		c2=int(input(),16)
	except:
		print('Bad Input on second ciphertext')
		c2=None
	return N,e1,e2,c1,c2

def get_input_fromfile():
	print('Enter the path of the first public key file')
	try:
		fname=input()
		with open(fname,'r') as f:
			key=RSA.importKey(f.read())
		N1=key.n
		e1=key.e
	except:
		print('Error on the first Public Key')
		N1=None
		e1=None
	print('Enter the path of the second public key file')
	try:
		fname=input()
		with open(fname,'r') as f:
			key=RSA.importKey(f.read())
		N2=key.n
		e2=key.e
	except:
		print('Error on the second Public Key')
		N2=None
		e2=None
	print('Enter the path of the first ciphertext file')
	try:
		fname=input()
		with open(fname,'r') as f:
			c1=int.from_bytes(base64.b64decode(f.read()),'big')
	except:
		print('Error on the second Public Key')
		c1=None
	print('Enter the path of the second ciphertext file')
	try:
		fname=input()
		with open(fname,'r') as f:
			c2=int.from_bytes(base64.b64decode(f.read()),'big')
	except:
		print('Error on the second Public Key')
		c2=None
	if N1==N2:
		N=N1
	else:
		print('RSA Modulus are not the same\nUnable to perform CommonRSA attack')
		N=None
	return N,e1,e2,c1,c2


n,e1,e2,c1,c2 = 0,0,0,0,0

if len(sys.argv)<2:
	usage()
	print('\t'+'-'*20)
	print('\tEnter "file" to load messages and keys from a file')
	print('\tEnter "raw" to give messages and keys from keyboard')
	choice = input()
	if choice=='file':
		n,e1,e2,c1,c2 = get_input_fromfile()
	elif choice=='raw':
		n,e1,e2,c1,c2 = get_input_stdin()
	else:
		exit(0)
elif sys.argv[1]=='file':
	n,e1,e2,c1,c2 = get_input_fromfile()
elif sys.argv[1]=='raw':
	n,e1,e2,c1,c2 = get_input_stdin()
else:
	usage()
	exit(0)


d,a,b = egcd(e1,e2)
m=(pow_mod(c1,a,n)*pow_mod(c2,b,n))%n
m=str(hex(m))[2:]
try:
	m=binascii.unhexlify(m)
except:
	m=binascii.unhexlify('0'+m)
print(m)
