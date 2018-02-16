import tornado.ioloop
import tornado.web
import tornado.websocket
import requests
from settings import *
from uuid import uuid4
from random import randint
from models import User
from ws_handler import WebSocket_Manager
from blockcypher import subscribe_to_address_webhook

from tornado.options import define, options
define('port', default=8000, type=int)


# ADD !~ Check to see if user exist in db
class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        uuid = self.get_secure_cookie('user_twitch_id')
        oauth = self.get_secure_cookie('user_oauth')
        if uuid and oauth:
            oauth =  oauth.decode('ascii')
            uuid = uuid.decode('ascii')
            is_token_valid = requests.get("https://api.twitch.tv/kraken/", headers={'Authorization': 'OAuth {}'.format(oauth)}, params={"client_id": TWITCH_CLIENT_ID}).json()['token']['valid']
            if is_token_valid:
                return User.get(User.twitch_id == uuid)


class MainHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.set_secure_cookie('test_cookie', 'test string', domain= DOMAIN)
        self.write(str(self.request))
        self.render('proto_test.html', domain = DOMAIN_BLOCK)



class AuthTwitchHandler(BaseHandler):
    def get(self):
        try:
            auth_code = self.get_argument("code") # Getting auth code from query
        except tornado.web.MissingArgumentError:
            self.redirect("/login/") # Redirect to Login Page
        payload = {
        "client_id":TWITCH_CLIENT_ID,
        "client_secret": TWITCH_SECRET,
        "code": auth_code,
        "grant_type": "authorization_code",
        "redirect_uri":TWITCH_REDIRECT_URL
        }
        r = requests.post("https://api.twitch.tv/kraken/oauth2/token", params=payload) # Request for oAuth token
        if r.status_code == requests.codes.ok:
            twitch_json = r.json()
            access_token = twitch_json["access_token"]
            refresh_token = twitch_json["refresh_token"]
            twitch_user = requests.get("https://api.twitch.tv/helix/users", headers={"Authorization": "Bearer {}".format(access_token)})
            twitch_user_data = twitch_user.json()['data'][0]
            twitch_id = twitch_user_data['id']
            try:
                user = User.get(User.twitch_id == twitch_id) # If user exist per unique Twitch ID grab User from database
            except User.DoesNotExist:
                user = User.create(uuid=uuid4(), hash_id=randint(1111,9999), email=twitch_user_data['email'],
                                   twitch_id=twitch_id, twitch_username= twitch_user_data['display_name']) # Create new User

            # Setting cookies
            #self.set_secure_cookie('user_uuid', bytes(user.uuid, 'ascii'), domain= DOMAIN)
            self.set_secure_cookie('user_twitch_id', bytes(twitch_id, 'ascii'), domain= DOMAIN)
            self.set_secure_cookie('user_oauth', bytes(access_token, 'ascii'), domain= DOMAIN)
            self.set_secure_cookie('user_refresh', bytes(refresh_token, 'ascii'))

            # CHANGE !~ redirect to home page
            #self.write("Successfully made User \n")
            #self.write(str(self.request))
            self.redirect('/')
            
        else:
            self.redirect("/login/") # Redirect to login page


# Clears all cookies
class LogoutHandler(BaseHandler):
    def get(self):
        self.clear_all_cookies(domain=DOMAIN)
        self.redirect('/')

# Handler for login page while NOT authenticated
class LoginHandler(BaseHandler):
    def get(self):
        if self.get_current_user() is None:
            self.set_secure_cookie('test_cookie', 'test string', domain= DOMAIN)
            self.render('proto_login.html', domain = DOMAIN_BLOCK, twitch_id = TWITCH_CLIENT_ID)
        else:
            self.redirect("/")


class NotificationHandler(BaseHandler):
    def get(self):
        self.render('ws_example.html', domain = DOMAIN_BLOCK)


wm = WebSocket_Manager() # Creating global WebSocket Manager instance
class NotificationSocket(tornado.websocket.WebSocketHandler):
    # Change when live
    def check_origin(self, origin):
        return True
    def open(self):
        self.write_message(self.get_secure_cookie('user_twitch_id'))
        self.sock_id = self.get_secure_cookie('user_twitch_id').decode('ascii')
        wm.add_session(self)

    def on_message(self, message):
        pass

    def on_close(self):
        wm.remove_session(self.sock_id)


# Webhook for blockcypher api to POST to
class BitcoinWebhook(BaseHandler):
    #Make post later
    def get(self):
	#add check if ws is not currently open and to ignore notif
	#still add to db logs for donations
        ws = wm.find_session(self.get_argument('id'))
        ws.write_message(str(self.request))
        ws.write_message('You received a new donation!')

# Used in AJAX post request
class UpdateBitcoinAddress(BaseHandler):
    @tornado.web.authenticated
    def post(self):
        user = self.get_current_user()
        try:
            new_address = self.get_argument('address')
        except tornado.web.MissingArgumentError:
            self.redirect('/')

        user.btc_address = new_address
        subscribe_to_address_webhook(callback_url='https://blockpop.xyz/btc/new-tx', subscription_address=new_address,
                                     event='confirmed-tx', api_key=BLOCK_CYPHER_KEY)



class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', MainHandler),
            (r'/login/', LoginHandler),
            (r'/logout', LogoutHandler),
            (r'/twitch/auth/', AuthTwitchHandler),
            (r'/asdf/', NotificationHandler),
            (r'/ws/', NotificationSocket),
            (r'/btc/', BitcoinWebhook),
        ]
        settings = {
            "template_path":TEMPLATE_PATH,
            "static_path":STATIC_PATH,
            "debug":DEBUG,
            "cookie_secret": COOKIE_SECRET,
            "login_url": "/login/"
        }
        tornado.web.Application.__init__(self, handlers, **settings)
if __name__ == "__main__":
    tornado.options.parse_command_line()
    app = Application()
    app.listen(options.port)
    tornado.ioloop.IOLoop.current().start()
