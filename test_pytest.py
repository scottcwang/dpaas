import datetime
import base64
import tempfile
import shutil
import time
from collections import namedtuple
import secrets

import nacl.signing
import pytest
import docker
from dotenv import load_dotenv
import flask_migrate
from bs4 import BeautifulSoup

from run import create_app
from Model import db


@pytest.fixture(scope='session')
def client():
    load_dotenv(dotenv_path='./.flaskenv')
    app = create_app()
    app.testing = True

    docker_client = docker.from_env()

    postgres_pulled = False
    try:
        docker_client.images.get("postgres:latest")
    except:
        docker_client.images.pull("postgres:latest")
        postgres_pulled = True
    postgres_container = docker_client.containers.run(
        "postgres:latest",
        ports={"5432/tcp": None},
        detach=True,
        remove=True,
        environment=["POSTGRES_PASSWORD=password"]
    )
    postgres_container.reload()
    postgres_port = postgres_container.ports["5432/tcp"][0]["HostPort"]
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:password@127.0.0.1:" + postgres_port

    redis_pulled = False
    try:
        docker_client.images.get("redis:latest")
    except:
        docker_client.images.pull("redis:latest")
        redis_pulled = True
    redis_container = docker_client.containers.run(
        "redis:latest",
        ports={"6379/tcp": None},
        detach=True,
        remove=True
    )
    redis_container.reload()
    redis_port = redis_container.ports["6379/tcp"][0]["HostPort"]
    app.config["REDIS_URL"] = "redis://127.0.0.1:" + redis_port

    time.sleep(10)

    migrate_dir = tempfile.mkdtemp()

    migrate = flask_migrate.Migrate(app, db)

    with app.app_context():
        flask_migrate.init(directory=migrate_dir)
        flask_migrate.migrate(directory=migrate_dir)
        flask_migrate.upgrade(directory=migrate_dir)

    shutil.rmtree(migrate_dir)

    c = app.test_client()

    with app.test_client() as client:
        yield client

    postgres_container.stop()
    if postgres_pulled:
        docker_client.images.remove("postgres")
    redis_container.stop()
    if redis_pulled:
        docker_client.images.remove("redis")


ClientKey = namedtuple('ClientKey', [
    'signing_key',
    'verify_key_b64'
])


@pytest.fixture(scope='session')
def client_key():
    signing_key = nacl.signing.SigningKey.generate()
    return ClientKey(
        signing_key,
        base64.urlsafe_b64encode(
            bytes(signing_key.verify_key)).decode()
    )


def root_req(client_verify_key_b64, future=False):
    return {
        'path': '/',
        'json': {
            'attributes': ['attr0', 'attr1', 'attr2'],
            'fit_model': 'PCA',
            'attribute_y_index': 2,
            'fit_arguments': {
                'epsilon': 1
            },
            'description': '# Title\nParagraph',
            'client_verify_key': client_verify_key_b64,
            'response_start_time': (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(minutes=(60 if future else 0))
            ).timestamp(),
            'response_end_time': (
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(minutes=(120 if future else 60))
            ).timestamp()
        }
    }


Collection = namedtuple('Collection', [
    'id',
    'public_key_b64',
    'private_key_secret'
])


@pytest.fixture(scope='session')
def collection(client, client_key):
    r = client.post(**root_req(client_key.verify_key_b64))
    return Collection(**r.json)


@pytest.fixture(scope='session')
def future_collection(client, client_key):
    r = client.post(**root_req(client_key.verify_key_b64, future=True))
    return Collection(**r.json)


def voucher_req(collection, client_serial, client_key):
    collection_public_key = nacl.public.PublicKey(
        base64.urlsafe_b64decode(collection.public_key_b64))

    client_serial_encrypt = nacl.public.Box(
        client_key.signing_key.to_curve25519_private_key(),
        collection_public_key
    ).encrypt(client_serial.encode())

    return {
        'path': '/' + collection.id + '/voucher',
        'json': {
            'collection_private_key_secret': collection.private_key_secret,
            'client_serial_encrypt': base64.urlsafe_b64encode(client_serial_encrypt).decode()
        }
    }


def entry_req(collection, client_serial, entry_serial, client_key):
    voucher_bytes = ','.join([
        client_serial,
        entry_serial,
        str(datetime.datetime.now(datetime.timezone.utc).timestamp())
    ]).encode()
    voucher_sign = client_key.signing_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    return {
        'path': '/' + collection.id + '/entry/' + voucher_b64
    }


def submit_req(entry_serial, csrf_token_form, session_token):
    return {
        'path': '/submit/' + entry_serial,
        'data': {
            'csrf_token': csrf_token_form,
            'session_token': session_token,
            'field_0': 0,
            'field_1': 1,
            'field_2': 2
        }
    }


def add_entry(client, collection, client_key):
    client_serial = secrets.token_urlsafe(16)
    r = client.post(
        **voucher_req(collection, client_serial, client_key)
    )
    entry_serial = r.json['entry_serial']

    r = client.get(
        **entry_req(collection, client_serial, entry_serial, client_key)
    )
    soup = BeautifulSoup(r.data, features="html.parser")
    csrf_token_form = soup.find(id='csrf_token')['value']
    session_token = soup.find(id='session_token')['value']
    entry_serial = soup.find(id='entry_serial').string

    r = client.post(
        **submit_req(entry_serial, csrf_token_form, session_token)
    )


def enqueue_req(collection, client_key):
    return {
        'path': '/' + collection.id + '/enqueue',
        'json': {
            'collection_private_key_secret': collection.private_key_secret
        }
    }


@pytest.fixture(scope='function')
def enqueued_collection(client, client_key):
    r = client.post(**root_req(client_key.verify_key_b64))
    collection = Collection(**r.json)

    add_entry(client, collection, client_key)

    time.sleep(10)

    add_entry(client, collection, client_key)

    r = client.post(**enqueue_req(collection, client_key))

    return collection


def test_root(client, client_key):
    r = client.post('/', data='a')
    assert r.status_code == 400 and r.json == 'Request is not JSON'

    r = client.post('/', json={'a': 'b'})
    assert r.status_code == 400 and r.json == 'JSON payload does not conform to schema'

    r = client.post(**root_req('a'))
    assert r.status_code == 400 and r.json == 'Public key could not be parsed'

    root_req_dict = root_req(client_key.verify_key_b64)
    root_req_dict['json']['fit_model'] = 'a'
    r = client.post(**root_req_dict)
    assert r.status_code == 400 and r.json == 'Fit model is not supported'

    root_req_dict = root_req(client_key.verify_key_b64)
    root_req_dict['json']['attribute_y_index'] = 3
    r = client.post(**root_req_dict)
    assert r.status_code == 400 and r.json == 'attribute_y_index invalid'

    r = client.post(**root_req(client_key.verify_key_b64))
    assert r.status_code == 201  # TODO validate schema of response JSON


def test_voucher(client, collection, future_collection, enqueued_collection, client_key):
    r = client.post('/' + collection.id + '/voucher', data='a')
    assert r.status_code == 400 and r.json == 'Request is not JSON'

    r = client.post('/' + collection.id + '/voucher', json={'a': 'b'})
    assert r.status_code == 400 and r.json == 'JSON payload does not conform to schema'

    voucher_req_dict = voucher_req(
        collection, secrets.token_urlsafe(16), client_key)
    voucher_req_dict['path'] = voucher_req_dict['path'].replace(
        collection.id, 'a')
    r = client.post(**voucher_req_dict)
    assert r.status_code == 404 and r.json == 'Collection ID not found'

    voucher_req_dict = voucher_req(
        future_collection, secrets.token_urlsafe(16), client_key)
    r = client.post(**voucher_req_dict)
    assert r.status_code == 410 and r.json == 'Not within collection interval'

    voucher_req_dict = voucher_req(
        enqueued_collection, secrets.token_urlsafe(16), client_key)
    r = client.post(**voucher_req_dict)
    assert r.status_code == 400 and r.json == 'Already enqueued'

    voucher_req_dict = voucher_req(
        collection, secrets.token_urlsafe(16), client_key)
    voucher_req_dict['json']['collection_private_key_secret'] = 'a'
    r = client.post(**voucher_req_dict)
    assert r.status_code == 400 and r.json == 'Incorrect collection private key secret'

    voucher_req_dict = voucher_req(
        collection, secrets.token_urlsafe(16), client_key)
    r = client.post(**voucher_req_dict)
    assert r.status_code == 201 # TODO validate schema of response JSON
