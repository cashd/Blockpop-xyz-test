import tornado.web
from models import User
from settings import *

class WebSocket_Manager:
    def __init__(self):
        self.d = dict()

    def add_session(self, NotificationSocket):
        self.d[NotificationSocket.sock_id] = NotificationSocket

    def remove_session(self, id):
        self.d.pop(id, None)

    def find_session(self, id):
        return self.d[id]




