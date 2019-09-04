import sys
import os
import json

sys.path.append(os.path.dirname(__file__))

from server import Server

with open('config.json') as f:
    config = json.load(f)

Server(
    config['hook-secret'],
    config['discord-hook'],
    config.get('name', None)
).run_sync(config['port'], len(sys.argv) > 1 and sys.argv[1] == '--debug')
