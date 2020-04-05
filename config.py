import os

basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = "postgresql://postgres:admin@localhost/postgres"

REDIS_URL = "redis://:MJqLybEKMYlbzQrS6QjdtbBw7jxn8zDY@redis-13595.c98.us-east-1-4.ec2.cloud.redislabs.com:13595/0"

SECRET_KEY = os.urandom(32)

REDIS_QUEUE_IS_ASYNC = False

# How to run from PS:
# $env:DPAAS_CONFIG_PATH = "config.py"
# $env:FLASK_APP = "run.py"
# flask run
