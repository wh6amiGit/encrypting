#!usr/bin/python3

import os, sys, base64, pathlib, secrets, getpass
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_salt(salt_size=16):
	return secrets.token_bytes(salt_size)

def get_key(salt, password):
	kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
	return kdf.derive(password.encode())

def load_salt(salt_file='salt.salt'):
	return open(salt_file, 'rb').read()

def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True, salt_file='salt.salt'):
	if load_existing_salt:
		salt = load_salt()

	elif save_salt:
		salt = generate_salt(salt_size)
		with open(salt_file, 'wb') as file_salt:
			file_salt.write(salt)

	geting_key = get_key(salt, password)
	get_key(salt, password)
	return base64.urlsafe_b64encode(geting_key)

def encrypt(filename, key):
	f = Fernet(key)
	with open(filename, 'rb') as file:
		file_data = file.read()
	encrypted_data = f.encrypt(file_data)
	with open(filename, 'wb') as file:
		file.write(encrypted_data)

def encrypt_folder(dir, key):
	for name in pathlib.Path(dir).glob('*'):
		if name.is_file():
			encrypt(name, key)
			print(f"[*] Encrypting {name} ")
		elif name.is_dir():
			encrypt_folder(name, key)

if __name__ == '__main__':
	if len(sys.argv) == 3:
		path = str(sys.argv[1])
		long_salt = int(sys.argv[2])
		password = getpass.getpass("Pick a password for encryption > ")
		key = generate_key(password, salt_size=long_salt, save_salt=True)
		try:
			if os.path.isfile(path):
				encrypt(path, key)
			elif os.path.isdir(path):
				encrypt_folder(path, key)
		except PermissionError:
			print("[-] You dont have a permission for this folder!!!")

	else:
		print(f"Usage: python {sys.argv[0]} < folder for encrypt > < salt size > ")
