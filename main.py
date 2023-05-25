from api_rubika import  Bot
auth = "auth in requests"
privatekey = "your private key"
bot = Bot(auth,privatekey)

print(bot.sendMessage("g0BTkrT04c9eac7ab2c1d71c71a192e0","hi everybody\nthis message sended using encryption of rubika v6 "))
