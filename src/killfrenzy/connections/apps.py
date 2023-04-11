from django.apps import AppConfig
import os

import web_socket
import clear

from django.conf import settings

class ConnectionsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'connections'

    def ready(self):
        if settings.DEBUG:
            env = os.environ.get("WEBSERVER_SET")

            if env is not None:
                #web_socket.socket_c.start()
                clear.clear_c.start()
            else:
                os.environ["WEBSERVER_SET"] = 'True'
        else:
            os.environ["WEBSERVER_SET"] = 'True'
            #web_socket.socket_c.start()
            clear.clear_c.start()
            print("Web socket and clearer both running.")