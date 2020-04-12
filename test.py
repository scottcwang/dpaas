import jwt
import secrets
import pickle
import requests
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from diffprivlib.models import pca

from bs4 import BeautifulSoup

hostname = 'http://127.0.0.1:5000'

client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
client_public_key_pem = client_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

r = requests.post(url=hostname + '/', data='a')
assert r.status_code == 400 and r.json() == 'Request is not JSON'

r = requests.post(url=hostname + '/', json={'a': 'b'})
assert r.status_code == 400 and r.json() == 'JSON payload does not conform to schema'

r = requests.post(
    url=hostname + '/',
    json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'public_key': 'a',
        'response_start_time': datetime.now().isoformat(),
        'response_end_time': (datetime.now() + timedelta(seconds=60)).isoformat()
    })
assert r.status_code == 400 and r.json() == 'Public key could not be parsed'

r = requests.post(
    url=hostname + '/',
    json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'a',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'public_key': client_public_key_pem.decode('utf-8'),
        'response_start_time': datetime.now().isoformat(),
        'response_end_time': (datetime.now() + timedelta(seconds=60)).isoformat()
    })
assert r.status_code == 400 and r.json() == 'Fit model is not supported'

r = requests.post(
    url=hostname + '/',
    json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 3,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'public_key': client_public_key_pem.decode('utf-8'),
        'response_start_time': datetime.now().isoformat(),
        'response_end_time': (datetime.now() + timedelta(seconds=60)).isoformat()
    })
assert r.status_code == 400 and r.json() == 'attribute_y_index invalid'

r = requests.post(
    url=hostname + '/',
    json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'public_key': client_public_key_pem.decode('utf-8'),
        'response_start_time': datetime.now().isoformat(),
        'response_end_time': (datetime.now() + timedelta(seconds=60)).isoformat()
    })
assert r.status_code == 201
collection_id = r.json()

r = requests.post(
    url=hostname + '/',
    json={
        'attributes': ['attr0', 'attr1', 'attr2'],
        'fit_model': 'PCA',
        'attribute_y_index': 2,
        'fit_arguments': {
            'epsilon': 1
        },
        'description': '# Title\nParagraph',
        'public_key': client_public_key_pem.decode('utf-8'),
        'response_start_time': (datetime.now() + timedelta(seconds=60)).isoformat(),
        'response_end_time': (datetime.now() + timedelta(seconds=120)).isoformat()
    })
assert r.status_code == 201
future_collection_id = r.json()

r = requests.post(url=hostname + '/' + str(collection_id) + '/token/a')
assert r.status_code == 400 and r.json() == 'Unknown action'

r = requests.post(url=hostname + '/' +
                  str(future_collection_id) + '/token/entry')
assert r.status_code == 410 and r.json() == 'Not within collection interval'

r = requests.post(url=hostname + '/' +
                  str(future_collection_id) + '/token/status')
assert r.status_code == 201

r = requests.post(url=hostname + '/0/token/entry')
assert r.status_code == 404

r = requests.post(url=hostname + '/' + str(collection_id) + '/token/entry')
assert r.status_code == 400 and r.json() == 'No nonce provided for entry action'

nonce = secrets.token_urlsafe()

r = requests.post(
    url=hostname + '/' + str(collection_id) + '/token/entry',
    data=nonce
)
assert r.status_code == 201

client_jwt = jwt.encode(
    payload={
        'jti': nonce,
        'iat': datetime.now().timestamp()
    },
    key=client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm='RS256'
).decode('utf-8')

r = requests.get(url=hostname + '/0/entry/' + client_jwt)
assert r.status_code == 404

r = requests.get(url=hostname + '/' +
                 str(future_collection_id) + '/entry/' + client_jwt)
assert r.status_code == 410 and r.json() == 'Not within collection interval'

bad_client_jwt = jwt.encode(
    payload={
        'jti': nonce
    },
    key=client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm='RS256'
).decode('utf-8')
r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + bad_client_jwt)
assert r.status_code == 400 and r.json() == 'Token does not contain issuance time'

bad_client_jwt = jwt.encode(
    payload={
        'iat': datetime.now().timestamp()
    },
    key=client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm='RS256'
).decode('utf-8')
r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + bad_client_jwt)
assert r.status_code == 400 and r.json() == 'Token does not contain nonce'

r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + client_jwt)
assert r.status_code == 200
soup = BeautifulSoup(r.content, features="html.parser")
csrf_token_form = soup.find(id='csrf_token')['value']
session_token = soup.find(id='session_token')['value']
csrf_token_cookie = r.cookies['session']

r = requests.post(url=hostname + '/0/submit')
assert r.status_code == 404

r = requests.post(
    url=hostname + '/' + str(collection_id) + '/submit',
    data={
        'csrf_token': csrf_token_form,
        'session_token': session_token,
        'field_0': 0,
        'field_1': 1,
        'field_2': 2
    },
    cookies={
        'session': csrf_token_cookie
    }
)
assert r.status_code == 200


# add a second value

nonce = secrets.token_urlsafe()

r = requests.post(
    url=hostname + '/' + str(collection_id) + '/token/entry',
    data=nonce
)
assert r.status_code == 201

client_jwt = jwt.encode(
    payload={
        'jti': nonce,
        'iat': datetime.now().timestamp()
    },
    key=client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm='RS256'
).decode('utf-8')

r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + client_jwt)
assert r.status_code == 200
soup = BeautifulSoup(r.content, features="html.parser")
csrf_token_form = soup.find(id='csrf_token')['value']
session_token = soup.find(id='session_token')['value']
csrf_token_cookie = r.cookies['session']

r = requests.post(url=hostname + '/0/submit')
assert r.status_code == 404

r = requests.post(
    url=hostname + '/' + str(collection_id) + '/submit',
    data={
        'csrf_token': csrf_token_form,
        'session_token': session_token,
        'field_0': 0,
        'field_1': 1,
        'field_2': 2
    },
    cookies={
        'session': csrf_token_cookie
    }
)
assert r.status_code == 200

r = requests.get(hostname + '/' + str(collection_id) + '/status/' + client_jwt)
assert r.status_code == 400 and r.json(
) == 'Token contains nonce for non-entry action'

client_jwt = jwt.encode(
    payload={
        'iat': datetime.now().timestamp()
    },
    key=client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm='RS256'
).decode('utf-8')

r = requests.get(hostname + '/' + str(collection_id) + '/status/' + client_jwt)
assert r.status_code == 403 and r.json() == 'A corresponding session was not found'

r = requests.post(hostname + '/' + str(collection_id) + '/token/status')
assert r.status_code == 201

r = requests.get(hostname + '/' + str(collection_id) + '/status/' + client_jwt)
assert r.status_code == 204

# cross-use a token
r = requests.post(hostname + '/' + str(collection_id) +
                  '/enqueue/' + client_jwt)
assert r.status_code == 403 and r.json() == 'A corresponding session was not found'

r = requests.post(hostname + '/' + str(collection_id) + '/token/enqueue')
assert r.status_code == 201

client_jwt = jwt.encode(
    payload={
        'iat': datetime.now().timestamp()
    },
    key=client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), algorithm='RS256'
).decode('utf-8')

r = requests.post(hostname + '/' + str(collection_id) +
                  '/enqueue/' + client_jwt)
assert r.status_code == 202

content = None

while content == None:
    r = requests.post(hostname + '/' + str(collection_id) + '/token/status')
    assert r.status_code == 201

    client_jwt = jwt.encode(
        payload={
            'iat': datetime.now().timestamp()
        },
        key=client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ), algorithm='RS256'
    ).decode('utf-8')

    r = requests.get(hostname + '/' + str(collection_id) +
                     '/status/' + client_jwt)
    if r.status_code == 200:
        content = r.content

pickle_load = pickle.loads(r.content)
assert type(pickle_load) == pca.PCA
