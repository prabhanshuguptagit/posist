#!/usr/bin/python -u
import datetime
import random
from hashlib import md5

from Crypto.Cipher import AES
import base64, os

document = {}

nodeCount = 0
genesisReferenceNode = False
padding_character = "{"

#AES code from https://gist.github.com/syedrakib/d71c463fc61852b8d366

def generate_secret_key_for_AES_cipher():
	# AES key length must be either 16, 24, or 32 bytes long
	AES_key_length = 16 # use larger value in production
	# generate a random secret key with the decided key length
	# this secret key will be used to create AES cipher for encryption/decryption
	secret_key = os.urandom(AES_key_length)
	# encode this secret key for storing safely in database
	encoded_secret_key = base64.b64encode(secret_key)
	return encoded_secret_key

def encrypt_message(private_msg, encoded_secret_key, padding_character):
	# decode the encoded secret key
	secret_key = base64.b64decode(encoded_secret_key)
	# use the decoded secret key to create a AES cipher
	cipher = AES.new(secret_key)
	# pad the private_msg
	# because AES encryption requires the length of the msg to be a multiple of 16
	padded_private_msg = private_msg + (padding_character * ((16-len(private_msg)) % 16))
	# use the cipher to encrypt the padded message
	encrypted_msg = cipher.encrypt(padded_private_msg)
	# encode the encrypted msg for storing safely in the database
	encoded_encrypted_msg = base64.b64encode(encrypted_msg)
	# return encoded encrypted message
	return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, encoded_secret_key, padding_character):
	# decode the encoded encrypted message and encoded secret key
	print encoded_secret_key
	secret_key = base64.b64decode(encoded_secret_key)
	encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	# use the decoded secret key to create a AES cipher
	cipher = AES.new(secret_key)
	# use the cipher to decrypt the encrypted message
	decrypted_msg = cipher.decrypt(encrypted_msg)
	# unpad the encrypted message
	unpadded_private_msg = decrypted_msg.rstrip(padding_character)
	# return a decrypted original private message
	return unpadded_private_msg

class Node:
	timestamp = ''
	data = {}
	nodeNumber = 1
	nodeId = ''
	referenceNodeId = ''
	childReferenceNodeId = []
	genesisReferenceNodeId = ''
	hashValue = ''

	def encrypt(self):
		global padding_character
		global generate_secret_key_for_AES_cipher
		global encrypt_message
		secret_key = generate_secret_key_for_AES_cipher()
		self.data = encrypt_message(self.data, secret_key, padding_character)
		return secret_key

	def decrypt(self, secret_key):
		global decrypt_message
		global padding_character
		decrypted_msg = decrypt_message(self.data, secret_key, padding_character)
		return decrypted_msg

	def __init__(self, value, ownerId, ownerName, parentNode= None):
		global genesisReferenceNode
		global nodeCount
		self.nodeId = random.getrandbits(32)
		if( genesisReferenceNode == False ):
			self.referenceNodeId = None #genesisNode
			genesisReferenceNode = self.nodeId

		self.timestamp = datetime.datetime.now()
		self.genesisReferenceNodeId =  genesisReferenceNode
		
		self.referenceNodeId = parentNode
		self.childReferenceNodeId = []

		# Check if children's sum is less than parent
		# for nodes in document[parentNode].childReferenceNodeId:
		# 	pass #check values

		if(parentNode is not None):
			print("Creating Genesis node...")
			document[parentNode].childReferenceNodeId.append({self.nodeId : self})
		# self.hashValue = ''

		self.data = str(ownerId) + ';' +  str(value) + ';' + str(ownerName) + ';' + md5(str(value) + str(ownerId) + str(ownerName)).hexdigest()


		nodeCount = nodeCount + 1
		self.nodeNumber = nodeCount

		document[self.nodeId] = self

		self.print_details()
		

	def print_details(self):

		# print("Data is: " + self.data)
		print("===================")
		print("Record created")
		print self
		print("Secret key is: " + self.encrypt())

		# print("Encrypted data is: " + self.data)

		print("Number of nodes: " + str(nodeCount))

		print("===================")

	def __str__(self):
		return str("Record ID: " + str(self.nodeId) + " \nChildren : [" + ', '.join([str(x) for x in self.childReferenceNodeId])  + "]") 

def createNode():
	ownerName = raw_input("Enter Your name: ")
	ownerId = raw_input("Enter Your ID: ")
	value = raw_input("Enter Value: ")

	if( genesisReferenceNode == False ):
		node = Node(value, ownerId, ownerName)
	else:
		parentNode = raw_input("Enter parent Node ID: ")
		node = Node(value, ownerId, ownerName, parentNode)

def viewNode():
	nodeId = raw_input("Enter Record ID: ")
	secretKey = raw_input("Enter secret key: ")

	try:
		node = document[long(float(nodeId))]
	except:
		print "Record not found"
		return ''
	print node.decrypt(secretKey).split(';')[1]

def editNode():
	nodeId = raw_input("Enter Record ID: ")
	secretKey = raw_input("Enter secret key: ")

	try:
		node = document[long(float(nodeId))]
	except:
		print "Record not found"
		return ''
	print node.decrypt(secretKey)

	ownerName = raw_input("Enter new owner name: ")
	ownerId = raw_input("Enter new owner ID: ")
	value = raw_input("Enter Value: ")

	if( genesisReferenceNode == False ):
		node = Node(value, ownerId, ownerName)
	else:
		parentNode = raw_input("Enter new parent Node ID: ")
		node = Node(value, ownerId, ownerName, parentNode)

def main():
	input = 1
	while input != 0:
		print '''
		Menu:
		==================================
		[1]: Add new record
		[2]: View record
		[3]: Edit record
		[0]: Exit
		'''
		input = raw_input()

		if input == '1':
			createNode()
		
		if input == '2':
			viewNode()

		# if input == '3':
		# 	editNode()


    # node2 = Node(2.01, 'prabhanshu@gmail', 'prabhanshu', node1.nodeId)

    # print node2
    # print node1 

if __name__ == "__main__":
    main()
