import sys
import os

sys.path.append(os.path.dirname(__file__))

from server import Server

Server().run_sync()
