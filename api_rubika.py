import base64
from json import dumps, loads
from random import randint,choice
import urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from requests import post
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
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "abcdefghijklmnopqrstuvwxyz".upper()
		digits = "0123456789"
		for s in auth_enc:
			if s in lowercase:
				n += chr(((32 - (ord(s) - 97)) % 26) + 97)
			elif s in uppercase:
				n += chr(((29- (ord(s) - 65)) % 26) + 65)
			elif s in digits:
				n += chr(((13 - (ord(s)- 48)) % 10) + 48)
			else:
				n += s
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

	def decryptRsaOaep(private:str,data_enc:str):
		keyPair = RSA.import_key(private.encode("utf-8"))
		return PKCS1_OAEP.new(keyPair).decrypt(base64.b64decode(data_enc)).decode("utf-8")
class Bot:
	def __init__(self, auth, private_key=None,is_auth_send=True,base64decode_private=False,useragent=None):	
		if is_auth_send:
			self.auth = encryption.changeAuthType(auth)
			self.auth_send = auth
		else:
			self.auth = auth
			self.auth_send = encryption.changeAuthType(auth)
		if base64decode_private:
			private_key = loads(base64.b64decode(private_key).decode("utf-8"))['d']
		self.enc = encryption(self.auth,private_key if private_key else None)
		self.default_client = {
							"app_name":"Main",
							"app_version":"4.3.1",
							"platform":"Web",
							"package":"web.rubika.ir",
							"lang_code":"fa"
							}
		self.default_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0" if not useragent else useragent
	def get_url(self):
		p = None
		while 1:
			try:
				datax = {"api_version":"4","method":"getDCs","client":{"app_name":"Main","app_version":"4.3.1","platform":"Web","package":"web.rubika.ir","lang_code":"fa"}}
				p = post(json=datax,url='https://getdcmess.iranlms.ir/',headers={
        			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
					'Origin':'https://web.rubika.ir',
					'Referer':'https://web.rubika.ir/',
					'Host':'getdcmess.iranlms.ir'
        		}).json()
				break
			except Exception as e:
				print(e)
				continue
		p = p['data']['default_api_urls'][1]
		return p
	
	def send_data(self,input,method,client=None,api_version="6",tmp=False):
		p = None
		while 1:
			try:
				data_ = {
					"api_version":api_version,
					"auth" if not tmp else "tmp_session":self.auth_send if not tmp else self.auth,
					"data_enc":self.enc.encrypt(dumps({
						"method":method,
						"input":input,
						"client": client if client else self.default_client
					})),
				}
				if api_version == "6" and tmp == False:
					data_["sign"] = self.enc.makeSignFromData(data_["data_enc"])
				url:str = "https://messengerg2c"+str(randint(1,69))+".iranlms.ir/"
				p = post(json=data_,url=url,headers={'User-Agent': self.default_agent,
                    'Origin':'https://web.rubika.ir',
					'Referer':'https://web.rubika.ir/',
					'Host':url.replace("https://","").replace("/","")})
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
	
	def makeRandomTmpSession():
		chars = "abcdefghijklmnopqrstuvwxyz"
		tmp = ""
		for i in range(32):
			tmp += choice(chars)
		return tmp
	
	def sendCode(phone:str,type="SMS"):
		input = {
      		"phone_number":phone,
        	"send_type":"SMS"
        }
		method = "sendCode"
		tmp = Bot.makeRandomTmpSession()
		b = Bot(tmp,is_auth_send=False)  
		return tmp , b.send_data(input,method,api_version="5",tmp=True)
	
	def rsaKeyGenrate():
		keyPair = RSA.generate(1024)
		public = encryption.changeAuthType(base64.b64encode(keyPair.publickey().export_key()).decode("utf-8"))
		privarte = keyPair.export_key().decode("utf-8")
		return public,privarte
	
	def signIn(tmp,phone,phone_code,hash,public_key=None):
		public , private = Bot.rsaKeyGenrate()
		input = {
			"phone_number":phone,
			"phone_code_hash":hash,
			"phone_code":str(phone_code),
			"public_key":public if not public_key else public_key
		}
		method = "signIn"
		b = Bot(tmp,is_auth_send=False)  
		request = b.send_data(input,method,tmp=True)
		if request['status'] == "OK" and request['data']['status'] == "OK":
			auth = encryption.decryptRsaOaep(private,request['data']['auth'])
			guid = request['data']['user']['user_guid']	
			return auth , guid, private
		else:
			return None
	
	def registerDevice(self,systemversion,device_model,device_hash):
		input = {
			"token_type":"Web",
			"token":"",
			"app_version":"WB_4.3.1",
			"lang_code": "fa",
			"system_version": systemversion,
			"device_model": device_model,
			"device_hash" : device_hash
		}
		print(input)
		method = "registerDevice"
		return self.send_data(input,method)
	
	def getMyStickerSets(self):
		input = {}
		method = "getMyStickerSets"
		return self.send_data(input,method)
