import os
import dotenv

dotenv.load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_ECHO = False
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")

REDIS_URL = os.getenv("REDIS_URL")

SECRET_KEY = os.urandom(32)

WTF_CSRF_ENABLED = False

# How to delete the database for Heroku PostgreSQL:
# docker run -it postgres bash
# apt update
# apt upgrade
# apt install curl
# curl https://cli-assets.heroku.com/install-ubuntu.sh | sh
# heroku login # then log in
# heroku apps
# heroku pg:psql -a <app name>
# drop schema public cascade;
# create schema public;
# grant all on schema public to postgres;
# grant all on schema public to public;
