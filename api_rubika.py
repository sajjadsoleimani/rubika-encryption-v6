import base64
from json import dumps, loads
from random import randint
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from requests import post
import random
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class encryption:
	def __init__(self, auth:str, private_key:str=None):

		self.key = bytearray(self.secret(auth), "UTF-8")
		self.iv = bytearray.fromhex('00000000000000000000000000000000')
		if private_key:
			self.keypair = RSA.import_key(private_key.encode("utf-8"))

	def replaceCharAt(self, e, t, i):
		return e[0:t] + i + e[t + len(i):]

	def changeAuthType(auth_enc):
		"""this function lines 78511 to 78746 and decode it very hard about 3 ,4 hour 
			\nmake key of encryption to key of request 
		"""
		n = ""
		for s in auth_enc:
			n += chr(((32 - (ord(s) - 97)) % 26) + 97)
		return n
	
	def secret(self, e):
		t = e[0:8]
		i = e[8:16]
		n = e[16:24] + t + e[24:32] + i
		s = 0
		while s < len(n):
			e = n[s]
			if e >= '0' and e <= '9':
				t = chr((ord(e[0]) - ord('0') + 5) % 10 + ord('0'))
				n = self.replaceCharAt(n, s, t)
			else:
				t = chr((ord(e[0]) - ord('a') + 9) % 26 + ord('a'))
				n = self.replaceCharAt(n, s, t)
			s += 1
		return n

	def encrypt(self, text):
		raw = pad(text.encode('UTF-8'), AES.block_size)
		aes = AES.new(self.key, AES.MODE_CBC, self.iv)
		enc = aes.encrypt(raw)
		result = base64.b64encode(enc).decode('UTF-8')
		return result

	def decrypt(self, text):
		aes = AES.new(self.key, AES.MODE_CBC, self.iv)
		dec = aes.decrypt(base64.urlsafe_b64decode(text.encode('UTF-8')))
		result = unpad(dec, AES.block_size).decode('UTF-8')
		return result

	def makeSignFromData(self, data_enc:str):
		"""2000 line of rubika web encoded source 
		  \ndecoded and cleaned and summarized using pycryptodome
		"""
		sha_data = SHA256.new(data_enc.encode("utf-8"))
		signature = pkcs1_15.new(self.keypair).sign(sha_data)
		return base64.b64encode(signature).decode("utf-8")
class Bot:
	def __init__(self, auth, private_key,is_auth_send=True):	
		if is_auth_send:
			self.auth = encryption.changeAuthType(auth)
			self.auth_send = auth
		else:
			self.auth = auth
			self.auth_send = encryption.changeAuthType(auth)
		self.enc = encryption(self.auth,private_key)
		self.default_client = {
							"app_name":"Main",
							"app_version":"4.3.1",
							"platform":"Web",
							"package":"web.rubika.ir",
							"lang_code":"fa"
							}

	def send_data(self,input,method,client=None,api_version="6"):
		p = None
		while 1:
			try:
				data_ = {
					"api_version":api_version,
					"auth":self.auth_send,
					"data_enc":self.enc.encrypt(dumps({
						"method":method,
						"input":input,
						"client": client if client else self.default_client
					})),
				}
				data_["sign"] = self.enc.makeSignFromData(data_["data_enc"])
				
				url = "https://messengerg2c"+str(random.randint(1,52))+".iranlms.ir/"
				print(url)
				p = post(json=data_,url=url)
				p = p.json()
				break
			except Exception as e:
				print(e)
				continue
		p = loads(self.enc.decrypt(p["data_enc"]))
		return p
	
	def sendMessage(self, chat_id, text, message_id=None):
		input = {
			"object_guid":chat_id,
			"rnd":f"{randint(100000,900000)}",
			"text":text,
		}
		method = "sendMessage"
		if message_id:
			input["reply_to_message_id"] = message_id
		return self.send_data(input,method)
	