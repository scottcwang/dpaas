import os
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
    docker_client = docker.from_env()

    postgres_pulled = False
    try:
        docker_client.images.get("postgres:latest")
    except:
        docker_client.images.pull("postgres:latest")
        postgres_pulled = True
    postgres_container = docker_client.containers.run(
        "postgres:latest",
        detach=True,
        remove=True,
        environment=["POSTGRES_PASSWORD=password"],
        network='dpaas_devcontainer_default'
    )
    postgres_container.reload()
    os.environ["SQLALCHEMY_DATABASE_URI"] = "postgresql://postgres:password@" + \
        postgres_container.attrs["Config"]["Hostname"] + ":5432"

    redis_pulled = False
    try:
        docker_client.images.get("redis:latest")
    except:
        docker_client.images.pull("redis:latest")
        redis_pulled = True
    redis_container = docker_client.containers.run(
        "redis:latest",
        detach=True,
        remove=True,
        network='dpaas_devcontainer_default'
    )
    redis_container.reload()
    os.environ["REDIS_URL"] = "redis://" + \
        redis_container.attrs["Config"]["Hostname"] + ":6379"

    load_dotenv(dotenv_path='./.flaskenv')
    app = create_app()
    app.testing = True

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


def create_collection(client, client_key):
    r = client.post(**root_req(client_key.verify_key_b64))
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
        'path': '/entry/' + voucher_b64
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


def redeem_voucher_for_entry_form(client, collection, client_key):
    client_serial = secrets.token_urlsafe(16)
    r = client.post(
        **voucher_req(collection, client_serial, client_key)
    )
    entry_serial = r.json['entry_serial']

    return entry_req(collection, client_serial, entry_serial, client_key)


def enqueue_req(collection, client_key):
    return {
        'path': '/' + collection.id + '/enqueue',
        'json': {
            'collection_private_key_secret': collection.private_key_secret
        }
    }


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


def test_voucher(client, client_key):
    collection = create_collection(client, client_key)

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

    root_req_dict = root_req(client_key.verify_key_b64)
    root_req_dict['json']['response_end_time'] = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(seconds=10)
    ).timestamp()
    r = client.post(**root_req_dict)
    past_collection = Collection(**r.json)
    time.sleep(20)
    r = client.post(**voucher_req(past_collection, 'a', client_key))
    assert r.status_code == 410 and r.json == 'Not within collection interval'

    root_req_dict = root_req(client_key.verify_key_b64)
    root_req_dict['json']['response_start_time'] = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=60)
    ).timestamp()
    root_req_dict['json']['response_end_time'] = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(minutes=120)
    ).timestamp()
    r = client.post(**root_req_dict)
    past_collection = Collection(**r.json)
    r = client.post(**voucher_req(past_collection, 'a', client_key))
    assert r.status_code == 410 and r.json == 'Not within collection interval'

    r = client.post(**root_req(client_key.verify_key_b64))
    enqueued_collection = Collection(**r.json)
    r = client.post(**enqueue_req(enqueued_collection, client_key))
    r = client.post(**voucher_req(enqueued_collection, 'a', client_key))
    assert r.status_code == 400 and r.json == 'Already enqueued'

    voucher_req_dict = voucher_req(
        collection, secrets.token_urlsafe(16), client_key)
    voucher_req_dict['json']['collection_private_key_secret'] = 'a'
    r = client.post(**voucher_req_dict)
    assert r.status_code == 400 and r.json == 'Incorrect collection private key secret'

    voucher_req_dict = voucher_req(
        collection, secrets.token_urlsafe(16), client_key)
    r = client.post(**voucher_req_dict)
    assert r.status_code == 201  # TODO validate schema of response JSON

    r = client.post(**voucher_req_dict)
    assert r.status_code == 400 and r.json == 'Client serial already used'


def test_entry(client, client_key):
    collection = create_collection(client, client_key)

    voucher_bytes = ','.join([
        'a',
        'a'
    ]).encode()
    voucher_sign = client_key.signing_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    r = client.get('/entry/' + voucher_b64)
    assert r.status_code == 400 and r.json == 'Voucher contains fewer than three values'

    voucher_bytes = ','.join([
        'a',
        'a',
        str(datetime.datetime.now(datetime.timezone.utc).timestamp()),
        'a'
    ]).encode()
    voucher_sign = client_key.signing_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    r = client.get('/entry/' + voucher_b64)
    assert r.status_code == 400 and r.json == 'Voucher contains more than three values'

    voucher_bytes = ','.join([
        'a',
        'a',
        'a'
    ]).encode()
    voucher_sign = client_key.signing_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    r = client.get('/entry/' + voucher_b64)
    assert r.status_code == 400 and r.json == 'Timestamp invalid'

    voucher_bytes = ','.join([
        'a',
        'a',
        str(datetime.datetime.now(datetime.timezone.utc).timestamp())
    ]).encode()
    voucher_sign = client_key.signing_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    r = client.get('/entry/' + voucher_b64)
    assert r.status_code == 404 and r.json == 'Entry does not exist'

    r = client.post(
        **voucher_req(collection, secrets.token_urlsafe(16), client_key)
    )
    entry_serial = r.json['entry_serial']
    voucher_bytes = ','.join([
        secrets.token_urlsafe(16),
        entry_serial,
        str(datetime.datetime.now(datetime.timezone.utc).timestamp())
    ]).encode()
    voucher_sign = client_key.signing_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    r = client.get('/entry/' + voucher_b64)
    assert r.status_code == 400 and r.json == 'Voucher client serial does not match registration'

    client_serial = secrets.token_urlsafe(16)
    r = client.post(
        **voucher_req(collection, client_serial, client_key)
    )
    entry_serial = r.json['entry_serial']
    voucher_bytes = ','.join([
        client_serial,
        entry_serial,
        str((datetime.datetime.now(datetime.timezone.utc) -
             datetime.timedelta(seconds=120)).timestamp())
    ]).encode()
    voucher_sign = client_key.signing_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    r = client.get('/entry/' + voucher_b64)
    assert r.status_code == 400 and r.json == 'Voucher not issued and registered at same time'

    root_req_dict = root_req(client_key.verify_key_b64)
    root_req_dict['json']['response_end_time'] = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(seconds=10)
    ).timestamp()
    r = client.post(**root_req_dict)
    past_collection = Collection(**r.json)
    r = client.post(**voucher_req(past_collection, 'a', client_key))
    entry_serial = r.json['entry_serial']
    time.sleep(20)
    r = client.get(**entry_req(past_collection, 'a', entry_serial, client_key))
    assert r.status_code == 410 and r.json == 'Not within collection interval'

    r = client.post(**root_req(client_key.verify_key_b64))
    enqueued_collection = Collection(**r.json)
    r = client.post(**voucher_req(enqueued_collection, 'a', client_key))
    entry_serial = r.json['entry_serial']
    r = client.post(**enqueue_req(enqueued_collection, client_key))
    r = client.get(**entry_req(enqueued_collection,
                               'a', entry_serial, client_key))
    assert r.status_code == 400 and r.json == 'Already enqueued'

    client_serial = secrets.token_urlsafe(16)
    r = client.post(
        **voucher_req(collection, client_serial, client_key)
    )
    entry_serial = r.json['entry_serial']
    voucher_bytes = ','.join([
        client_serial,
        entry_serial,
        str(datetime.datetime.now(datetime.timezone.utc).timestamp())
    ]).encode()
    bad_client_key = nacl.signing.SigningKey.generate()
    voucher_sign = bad_client_key.sign(voucher_bytes)
    voucher_b64 = base64.urlsafe_b64encode(voucher_sign).decode()
    r = client.get('/entry/' + voucher_b64)
    assert r.status_code == 400 and r.json == 'Voucher could not be verified'

    redeem_voucher_for_entry_form_dict = redeem_voucher_for_entry_form(
        client, collection, client_key)
    r = client.get(**redeem_voucher_for_entry_form_dict)
    assert r.status_code == 200

    # TODO Test returned HTML has correct form fields

    r = client.get(**redeem_voucher_for_entry_form_dict)
    assert r.status_code == 400 and r.json == 'Voucher already redeemed for a form'


def parse_entry_form(data):
    soup = BeautifulSoup(data, features="html.parser")
    csrf_token_form = soup.find(id='csrf_token')['value']
    session_token = soup.find(id='session_token')['value']
    entry_serial = soup.find(id='entry_serial').string

    return {
        'entry_serial': entry_serial,
        'csrf_token_form': csrf_token_form,
        'session_token': session_token
    }


def test_submit(client, client_key):
    collection = create_collection(client, client_key)

    r = client.get(
        **redeem_voucher_for_entry_form(client, collection, client_key))
    parse_entry_form_dict = parse_entry_form(r.data)
    parse_entry_form_dict['entry_serial'] = 'a'
    r = client.post(**submit_req(**parse_entry_form_dict))
    assert r.status_code == 404 and r.json == 'Entry does not exist'

    r = client.get(
        **redeem_voucher_for_entry_form(client, collection, client_key))
    submit_req_dict = submit_req(**parse_entry_form(r.data))
    submit_req_dict['data']['csrf_token'] = 'a'
    r = client.post(**submit_req_dict)
    assert r.status_code == 400 and r.json == 'Form data does not conform to schema, or CSRF token does not match'

    r = client.get(
        **redeem_voucher_for_entry_form(client, collection, client_key))
    submit_req_dict = submit_req(**parse_entry_form(r.data))
    del submit_req_dict['data']['field_0']
    r = client.post(**submit_req_dict)
    assert r.status_code == 400 and r.json == 'Form data does not conform to schema, or CSRF token does not match'

    root_req_dict = root_req(client_key.verify_key_b64)
    root_req_dict['json']['response_end_time'] = (
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(seconds=10)
    ).timestamp()
    r = client.post(**root_req_dict)
    past_collection = Collection(**r.json)
    r = client.post(**voucher_req(past_collection, 'a', client_key))
    entry_serial = r.json['entry_serial']
    r = client.get(
        **redeem_voucher_for_entry_form(client, past_collection, client_key))
    time.sleep(20)
    r = client.post(**submit_req(**parse_entry_form(r.data)))
    assert r.status_code == 410 and r.json == 'Not within collection interval'

    r = client.post(**root_req(client_key.verify_key_b64))
    enqueued_collection = Collection(**r.json)
    r = client.post(**voucher_req(enqueued_collection, 'a', client_key))
    entry_serial = r.json['entry_serial']
    r = client.get(**entry_req(enqueued_collection,
                               'a', entry_serial, client_key))
    data = r.data
    r = client.post(**enqueue_req(enqueued_collection, client_key))
    r = client.post(**submit_req(**parse_entry_form(data)))
    assert r.status_code == 400 and r.json == 'Already enqueued'

    r = client.get(
        **redeem_voucher_for_entry_form(client, collection, client_key))
    submit_req_dict = submit_req(**parse_entry_form(r.data))
    submit_req_dict['data']['session_token'] = 'a'
    r = client.post(**submit_req_dict)
    assert r.status_code == 403 and r.json == 'Incorrect session token'

    r = client.get(
        **redeem_voucher_for_entry_form(client, collection, client_key))
    submit_req_dict = submit_req(**parse_entry_form(r.data))
    r = client.post(**submit_req_dict)
    assert r.status_code == 200

    r = client.post(**submit_req_dict)
    assert r.status_code == 400 and r.json == 'Form already submitted'

    r = client.get(
        **redeem_voucher_for_entry_form(client, collection, client_key))
    submit_req_dict = submit_req(**parse_entry_form(r.data))
    submit_req_dict['data']['field_3'] = 'a'
    r = client.post(**submit_req_dict)
    assert r.status_code == 200


def queue_req(collection):
    return {
        'path': '/' + collection.id + '/enqueue',
        'json': {
            'collection_private_key_secret': collection.private_key_secret
        }
    }


def test_queue(client, client_key):
    collection = create_collection(client, client_key)

    r = client.post('/' + collection.id + '/enqueue', data='a')
    assert r.status_code == 400 and r.json == 'Request is not JSON'

    r = client.post('/' + collection.id + '/enqueue', json={'a': 'b'})
    assert r.status_code == 400 and r.json == 'JSON payload does not conform to schema'

    queue_req_dict = queue_req(collection)
    queue_req_dict['path'] = queue_req_dict['path'].replace(collection.id, 'a')
    r = client.post(**queue_req_dict)
    assert r.status_code == 404 and r.json == 'Collection ID not found'

    queue_req_dict = queue_req(collection)
    queue_req_dict['json']['collection_private_key_secret'] = 'a'
    r = client.post(**queue_req_dict)
    assert r.status_code == 400 and r.json == 'Incorrect collection private key secret'

    r = client.post(**queue_req(collection))
    assert r.status_code == 202

    r = client.post(**queue_req(collection))
    assert r.status_code == 400 and r.json == 'Already enqueued'
