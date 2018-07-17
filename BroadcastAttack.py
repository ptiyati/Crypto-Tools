#!/usr/bin/env python3
#https://github.com/aaossa
import sys
import binascii
import math
import gmpy2
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

def get_input_stdin():
	print('Enter the first RSA Modulus :',end='\t')
	try :
		N0=int(input(),16)
	except:
		print('Bad Input on firstmodulus')
		N0=None
	print('Enter the second RSA Modulus :',end='\t')
	try :
		N1=int(input(),16)
	except:
		print('Bad Input on second modulus')
		N1=None
	print('Enter the third RSA Modulus :',end='\t')
	try :
		N2=int(input(),16)
	except:
		print('Bad Input on third modulus')
		N2=None

	print('Enter first Ciphertext :',end='\t')
	try :
		c0=int(input(),16)
	except:
		print('Bad Input on first ciphertext')
		c0=None
	print('Enter second Ciphertext :',end='\t')
	try :
		c1=int(input(),16)
	except:
		print('Bad Input on second ciphertext')
		c1=None
	print('Enter third Ciphertext : ',end='\t')
	try :
		c2=int(input(),16)
	except:
		print('Bad Input on third ciphertext')
		c2=None
	return N0,N1,N2,c0,c1,c2

def get_input_fromfile():
	print('Enter the path of the first public key file')
	try:
		fname=input()
		with open(fname,'r') as f:
			key=RSA.importKey(f.read())
		N0=key.n
	except:
		print('Error on the first Public Key')
		N0=None
	print('Enter the path of the second public key file')
	try:
		fname=input()
		with open(fname,'r') as f:
			key=RSA.importKey(f.read())
		N1=key.n
	except:
		print('Error on the second Public Key')
		N1=None
	print('Enter the path of the third public key file')
	try:
		fname=input()
		with open(fname,'r') as f:
			key=RSA.importKey(f.read())
		N2=key.n
	except:
		print('Error on the third Public Key')
		N2=None
	print('Enter the path of the first ciphertext file')
	try:
		fname=input()
		with open(fname,'r') as f:
			c0=int.from_bytes(base64.b64decode(f.read()),'big')
	except:
		print('Error on the second Public Key')
		c0=None
	print('Enter the path of the second ciphertext file')
	try:
		fname=input()
		with open(fname,'r') as f:
			c1=int.from_bytes(base64.b64decode(f.read()),'big')
	except:
		print('Error on the second Public Key')
		c1=None
	print('Enter the path of the third ciphertext file')
	try:
		fname=input()
		with open(fname,'r') as f:
			c2=int.from_bytes(base64.b64decode(f.read()),'big')
	except:
		print('Error on the second Public Key')
		c2=None
	return N0,N1,N2,c0,c1,c2


sys.setrecursionlimit(10000)
gmpy2.get_context().precision = 4096
N0,N1,N2,c0,c1,c2=0,0,0,0,0,0

if len(sys.argv)<2:
	usage()
	print('\t'+'-'*20)
	print('\tEnter "file" to load messages and modulus from a file')
	print('\tEnter "raw" to give messages and modulus from keyboard')
	choice = input()
	if choice=='file':
		N0,N1,N2,c0,c1,c2 = get_input_fromfile()
	elif choice=='raw':
		N0,N1,N2,c0,c1,c2 = get_input_stdin()
	else:
		exit(0)
elif sys.argv[1]=='file':
	N0,N1,N2,c0,c1,c2 = get_input_fromfile()
elif sys.argv[1]=='raw':
	N0,N1,N2,c0,c1,c2 = get_input_stdin()
else:
	usage()
	exit(0)

N=N0*N1*N2

t0=c0*N1*N2*(modinv(N1*N2,N0))
t1=c1*N0*N2*(modinv(N0*N2,N1))
t2=c2*N0*N1*(modinv(N0*N1,N2))

mmm=(t0+t1+t2)%N
m=int(gmpy2.root(mmm,3))
m=str(hex(m))[2:]
m=binascii.unhexlify(m)
print(m)
