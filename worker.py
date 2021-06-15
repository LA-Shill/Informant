# !/usr/bin/env python
# Name:     worker.py
# By:       LA-Shill
# Date:     22.04.2021
# Version   0.1
# -----------------------------------------------

import os
from dotenv import load_dotenv
import redis
from rq import Worker, Queue, Connection

load_dotenv()
REDISTOGO_URL = os.getenv('REDISTOGO_URL')

listen = ['default']
redis_url = REDISTOGO_URL
conn = redis.from_url(redis_url)

if __name__ == '__main__':
    with Connection(conn):
        worker = Worker(list(map(Queue, listen)))
        worker.work()