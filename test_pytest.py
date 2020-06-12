import datetime
import base64
import tempfile
import shutil
import time
from collections import namedtuple

import nacl.signing
import pytest
import docker
from dotenv import load_dotenv
import flask_migrate

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


@pytest.fixture(scope='session')
def collection(client):
    client_signing_key = nacl.signing.SigningKey.generate()
    client_verify_key_encoded = base64.urlsafe_b64encode(
        bytes(client_signing_key.verify_key)).decode()

    r = client.post('/', json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'client_verify_key': client_verify_key_encoded,
        'response_start_time': datetime.datetime.now(datetime.timezone.utc).timestamp(),
        'response_end_time': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)).timestamp()
    })
    collection_id, collection_public_key_b64, collection_private_key_secret = r.json.split(
        ',')

    Collection = namedtuple('Collection',
                            [
                                'id',
                                'collection_public_key_b64',
                                'collection_private_key_secret',
                                'client_signing_key'
                            ])
    return Collection(
        collection_id,
        collection_public_key_b64, collection_private_key_secret,
        client_signing_key
    )


def test_root(client):
    r = client.post('/', data='a')
    assert r.status_code == 400 and r.json == 'Request is not JSON'

    r = client.post('/', json={'a': 'b'})
    assert r.status_code == 400 and r.json == 'JSON payload does not conform to schema'

    r = client.post('/', json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'client_verify_key': 'a',
        'response_start_time': datetime.datetime.now(datetime.timezone.utc).timestamp(),
        'response_end_time': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)).timestamp()
    })
    assert r.status_code == 400 and r.json == 'Public key could not be parsed'

    client_signing_key = nacl.signing.SigningKey.generate()
    client_verify_key_encoded = base64.urlsafe_b64encode(
        bytes(client_signing_key.verify_key)).decode()

    r = client.post('/', json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'a',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'client_verify_key': client_verify_key_encoded,
        'response_start_time': datetime.datetime.now(datetime.timezone.utc).timestamp(),
        'response_end_time': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)).timestamp()
    })
    assert r.status_code == 400 and r.json == 'Fit model is not supported'

    r = client.post('/', json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 3,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'client_verify_key': client_verify_key_encoded,
        'response_start_time': datetime.datetime.now(datetime.timezone.utc).timestamp(),
        'response_end_time': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)).timestamp()
    })
    assert r.status_code == 400 and r.json == 'attribute_y_index invalid'

    r = client.post('/', json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'client_verify_key': client_verify_key_encoded,
        'response_start_time': datetime.datetime.now(datetime.timezone.utc).timestamp(),
        'response_end_time': (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=60)).timestamp()
    })
    assert r.status_code == 201


def test_voucher(client, collection):
    r = client.post('/' + collection.id + '/voucher', data='a')
    assert r.status_code == 400 and r.json == 'Request is not JSON'

    r = client.post('/' + collection.id + '/voucher', json={'a': 'b'})
    assert r.status_code == 400 and r.json == 'JSON payload does not conform to schema'
