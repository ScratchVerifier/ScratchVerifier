import sys
import os
import json

sys.path.append(os.path.dirname(__file__))

from server import Server

with open('config.json') as f:
    config = json.load(f)

Server(config['hook-secret']).run_sync(config['port'])
