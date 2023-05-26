#login sample
from api_rubika import Bot

phone = str(input("phone : "))
tmp , data = Bot.sendCode(phone)
phone_code = str(input("code : "))
auth , guid , private = Bot.signIn(tmp,phone,phone_code,data['data']['phone_code_hash'])
bot = Bot(auth,private,False)
print(bot.registerDevice("Windows 10","Firefox 113","25010064641090201001011130"))
print(bot.getMyStickerSets())
print(bot.sendMessage(guid,"hi everybody\nthis message sended using encryption of rubika v6 "))
