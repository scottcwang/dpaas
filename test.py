import jwt
import secrets
import pickle
import base64
import requests
from datetime import datetime, timedelta
from diffprivlib.models import pca
import nacl.signing

from bs4 import BeautifulSoup

hostname = 'http://127.0.0.1:5000'

client_signing_key = nacl.signing.SigningKey.generate()
# client_public_key_encoded = str(client_signing_key.public_key.encode(encoder=nacl.encoding.URLSafeBase64Encoder)) # TODO figure out why nacl.encoding.*Encoder doesn't work
client_verify_key_encoded = base64.urlsafe_b64encode(
    bytes(client_signing_key.verify_key)).decode()

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
        'client_verify_key': 'a',
        'response_start_time': datetime.now().isoformat(),
        'response_end_time': (datetime.now() + timedelta(minutes=60)).isoformat()
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
        'client_verify_key': client_verify_key_encoded,
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
        'client_verify_key': client_verify_key_encoded,
        'response_start_time': datetime.now().isoformat(),
        'response_end_time': (datetime.now() + timedelta(minutes=60)).isoformat()
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
        'client_verify_key': client_verify_key_encoded,
        'response_start_time': datetime.now().isoformat(),
        'response_end_time': (datetime.now() + timedelta(minutes=60)).isoformat()
    })
assert r.status_code == 201
collection_id, collection_public_key_b64, collection_private_key_secret = r.json().split(',')

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
        'client_verify_key': client_verify_key_encoded,
        'response_start_time': (datetime.now() + timedelta(minutes=60)).isoformat(),
        'response_end_time': (datetime.now() + timedelta(minutes=120)).isoformat()
    })
assert r.status_code == 201
future_collection_id, _, _ = r.json().split(',')

r = requests.post(
    url=hostname + '/' + str(future_collection_id) + '/voucher',
    json={
        'collection_private_key_secret': collection_private_key_secret,
        'client_serial_encrypt': 'a'
    })
assert r.status_code == 410 and r.json() == 'Not within collection interval'

r = requests.post(
    url=hostname + '/0/voucher',
    json={
        'collection_private_key_secret': collection_private_key_secret,
        'client_serial_encrypt': 'a'
    })
assert r.status_code == 404

collection_public_key = nacl.public.PublicKey(
    base64.urlsafe_b64decode(collection_public_key_b64))
client_serial = secrets.token_bytes(16)
box = nacl.public.Box(
    client_signing_key.to_curve25519_private_key(), collection_public_key)
client_serial_encrypt = box.encrypt(client_serial)

r = requests.post(
    url=hostname + '/' + str(collection_id) + '/voucher',
    json={
        'collection_private_key_secret': collection_private_key_secret,
        'client_serial_encrypt': base64.urlsafe_b64encode(client_serial_encrypt).decode()
    })
assert r.status_code == 201
entry_serial = r.json()

# TODO Test that attempt to reuse client_serial_encrypt fails

voucher = ','.join(
    [base64.urlsafe_b64encode(client_serial).decode(), entry_serial, str(datetime.now().timestamp())])
voucher_sign = client_signing_key.sign(voucher.encode())
voucher_encode = base64.urlsafe_b64encode(voucher_sign).decode()

r = requests.get(url=hostname + '/0/entry/' + voucher_encode)
assert r.status_code == 404

r = requests.get(url=hostname + '/' +
                 str(future_collection_id) + '/entry/' + voucher_encode)
assert r.status_code == 410 and r.json() == 'Not within collection interval'

bad_voucher = ','.join(['1', '2'])
bad_voucher_sign = client_signing_key.sign(bad_voucher.encode())
bad_voucher_encode = base64.urlsafe_b64encode(bad_voucher_sign).decode()
r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + bad_voucher_encode)
assert r.status_code == 400 and r.json() == 'Voucher contains fewer than three values'

bad_voucher = ','.join(['1', '2', '3', '4'])
bad_voucher_sign = client_signing_key.sign(bad_voucher.encode())
bad_voucher_encode = base64.urlsafe_b64encode(bad_voucher_sign).decode()
r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + bad_voucher_encode)
assert r.status_code == 400 and r.json() == 'Voucher contains more than three values'

bad_client_serial = secrets.token_urlsafe(17)
bad_voucher = ','.join([bad_client_serial, entry_serial,
                        str(datetime.now().timestamp())])
bad_voucher_sign = client_signing_key.sign(bad_voucher.encode())
bad_voucher_encode = base64.urlsafe_b64encode(bad_voucher_sign).decode()
r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + bad_voucher_encode)
assert r.status_code == 400 and r.json(
) == 'Voucher client serial does not match registration'

# TODO test 'Entry serial not for this collection'

bad_voucher = ','.join([base64.urlsafe_b64encode(
    client_serial).decode(), secrets.token_urlsafe(17), str(datetime.now().timestamp())])
bad_voucher_sign = client_signing_key.sign(bad_voucher.encode())
bad_voucher_encode = base64.urlsafe_b64encode(bad_voucher_sign).decode()
r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + bad_voucher_encode)
assert r.status_code == 404 and r.json() == 'Entry does not exist'

bad_voucher = ','.join([base64.urlsafe_b64encode(
    client_serial).decode(), entry_serial, str((datetime.now() + timedelta(seconds=120)).timestamp())])
bad_voucher_sign = client_signing_key.sign(bad_voucher.encode())
bad_voucher_encode = base64.urlsafe_b64encode(bad_voucher_sign).decode()
r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + bad_voucher_encode)
assert r.status_code == 400 and r.json(
) == 'Voucher not issued and registered at same time'

r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + voucher_encode)
assert r.status_code == 200
soup = BeautifulSoup(r.content, features="html.parser")
csrf_token_form = soup.find(id='csrf_token')['value']
session_token = soup.find(id='session_token')['value']
entry_serial = soup.find(id='entry_serial').string
csrf_token_cookie = r.cookies['session']

r = requests.post(url=hostname + '/submit/0')
assert r.status_code == 404

r = requests.post(
    url=hostname + '/submit/' + str(entry_serial),
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

r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + voucher_encode)
assert r.status_code == 400 and r.json() == 'Voucher already redeemed for a form'

# add a second value

client_serial = secrets.token_bytes(16)
box = nacl.public.Box(
    client_signing_key.to_curve25519_private_key(), collection_public_key)
client_serial_encrypt = box.encrypt(client_serial)


r = requests.post(
    url=hostname + '/' + str(collection_id) + '/voucher',
    json={
        'collection_private_key_secret': collection_private_key_secret,
        'client_serial_encrypt': base64.urlsafe_b64encode(client_serial_encrypt).decode()
    })
assert r.status_code == 201
entry_serial = r.json()

voucher = ','.join(
    [base64.urlsafe_b64encode(client_serial).decode(), entry_serial, str(datetime.now().timestamp())])
voucher_sign = client_signing_key.sign(voucher.encode())
voucher_encode = base64.urlsafe_b64encode(voucher_sign).decode()

r = requests.get(url=hostname + '/' + str(collection_id) +
                 '/entry/' + voucher_encode)
assert r.status_code == 200
soup = BeautifulSoup(r.content, features="html.parser")
csrf_token_form = soup.find(id='csrf_token')['value']
session_token = soup.find(id='session_token')['value']
entry_serial = soup.find(id='entry_serial').string
csrf_token_cookie = r.cookies['session']

r = requests.post(url=hostname + '/submit/0')
assert r.status_code == 404

r = requests.post(
    url=hostname + '/submit/' + str(entry_serial),
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

# TODO Test unredeemed voucher is not used in model

r = requests.get(hostname + '/' + str(collection_id) + '/status')
assert r.status_code == 204

r = requests.post(
    url=hostname + '/' + str(collection_id) + '/enqueue',
    json={
        'collection_private_key_secret': 'a'
    })
assert r.status_code == 400 and r.json() == 'Incorrect collection private key secret'

r = requests.post(
    url=hostname + '/' + str(collection_id) + '/enqueue',
    json={
        'collection_private_key_secret': collection_private_key_secret
    })
assert r.status_code == 202

content = None

while content == None:
    r = requests.get(hostname + '/' + str(collection_id) + '/status')
    if r.status_code == 200:
        content = r.content

pickle_load = pickle.loads(r.content)
assert type(pickle_load) == pca.PCA
