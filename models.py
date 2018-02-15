from peewee import *

db = SqliteDatabase('/home/cashd/srv/BlockPop-xyz-prod/database.db')

class Base(Model):
	class Meta:
		database = db

class User(Base):
	uuid = CharField()
	hash_id = IntegerField()
	email = CharField()
	twitch_id = CharField()
	twitch_username = CharField()
	btc_address = CharField(default="")
	#twitch_profile_picture = CharField()
	#profile_bio = CharField()


class Transaction(Base):
	user = ForeignKeyField(User, related_name="transactions")
	rec_wallet_address = CharField()
	display_name = CharField()
	display_msg = CharField()
	#amount = IntegerField()
	currency_type = CharField()


def create_tables():
	db.connect()
	db.create_tables([User])



	
