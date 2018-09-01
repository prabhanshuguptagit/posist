import datetime
import random
from hashlib import md5

from Crypto.Cipher import AES
import base64, os

document = {}

nodeCount = 0
genesisReferenceNode = False

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
	#AES code from https://gist.github.com/syedrakib/d71c463fc61852b8d366
		global generate_secret_key_for_AES_cipher
		global encrypt_message
		padding_character = "{"
		secret_key = generate_secret_key_for_AES_cipher()
		self.data = encrypt_message(self.data, secret_key, padding_character)
		return secret_key

	def decrypt(self, key):
		global decrypt_message
		padding_character = "{"
		decrypted_msg = decrypt_message(self.data, secret_key, padding_character)
		return decrypt_message

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

		# for nodes in document[parentNode].childReferenceNodeId:
		# 	pass #check values
		if(parentNode is not None):
			document[parentNode].childReferenceNodeId.append({self.nodeId : self})
		# self.hashValue = ''

		self.data = str(ownerId) + ';' +  str(value) + ';' + str(ownerName) + ';' + md5(str(value) + str(ownerId) + str(ownerName)).hexdigest()

		print("Data is: " + self.data)
		print("Secret key is" + self.encrypt())
		print("Encrypted data is: " + self.data)

		nodeCount = nodeCount + 1
		self.nodeNumber = nodeCount

		document[self.nodeId] = self
		print("nodeCount = " + str(nodeCount))

	def __str__(self):
		return str(str(self.nodeId) + " Children : [" + ', '.join([str(x) for x in self.childReferenceNodeId])  + "]") 

def main():
    node1 = Node(5.01, 'arun@123', 'arun')
    # Node(value, ownerID, ownerName)
    print node1

    node2 = Node(2.01, 'prabhanshu@gmail', 'prabhanshu', node1.nodeId)

    print node2
    print node1 

if __name__ == "__main__":
    main()
