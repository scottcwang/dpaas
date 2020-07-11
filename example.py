#!/usr/bin/env python3

import base64
import datetime
import secrets
import pickle

import requests

from nacl.signing import SigningKey
from nacl.public import PublicKey, Box

url = 'https://scottcwang-dpaas.herokuapp.com'

# Create a collection

print('Generating signing key')
signing_key = SigningKey.generate()

print('Creating collection')
req = requests.request(
    'POST',
    url + '/',
    json={
        'attributes': ['Height / cm', 'Weight / kg'],
        'fit_model': 'LinearRegression',
        'attribute_y_index': 1,
        'fit_arguments': {
            'epsilon': 1,
            'data_norm': 1
        },
        'description': '# Medical Study\n' +
        'We would like to gather information about your height and weight. ' +
        'Your data will be used to generate a differentially private model, ' +
        'which means that the model is mathematically guaranteed to keep your individual data private.',
        'client_verify_key': base64.urlsafe_b64encode(
            bytes(signing_key.verify_key)).decode(),
        'response_start_time': (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta()
        ).timestamp(),
        'response_end_time': (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=60)
        ).timestamp()
    }
)

resp = req.json()

collection_id = resp['id']
print('Received collection ID: ' + collection_id)

collection_public_key = PublicKey(
    base64.urlsafe_b64decode(resp['public_key'])
)

collection_public_key_client_private_key_box = Box(
    signing_key.to_curve25519_private_key(),
    collection_public_key
)

collection_private_key_secret = base64.urlsafe_b64encode(
    collection_public_key_client_private_key_box.decrypt(
        base64.urlsafe_b64decode(
            resp['collection_private_key_secret']
        )
    )
).decode()
print('Received collection private key secret: ' + collection_private_key_secret)

user_entry_urls = []

for _ in range(3):
    # Register a voucher client serial, which will be used to redeem an entry form

    client_serial = secrets.token_urlsafe()
    print('Registering client serial: ' + client_serial)

    client_serial_encrypt = base64.urlsafe_b64encode(
        collection_public_key_client_private_key_box.encrypt(
            client_serial.encode()
        )
    ).decode()

    req = requests.request(
        'POST',
        url + '/' + collection_id + '/voucher',
        json={
            'collection_private_key_secret': collection_private_key_secret,
            'client_serial_encrypt': client_serial_encrypt
        }
    )

    resp = req.json()

    entry_serial = resp['entry_serial']
    print('Received corresponding entry serial: ' + entry_serial)

    timestamp = datetime.datetime.now().timestamp()

    voucher = base64.urlsafe_b64encode(
        signing_key.sign(
            (client_serial + ',' + entry_serial + ',' + str(timestamp)).encode()
        )
    ).decode()

    # Give this link to the user:
    user_entry_urls.append(url + '/entry/' + voucher)

print('-----\nVisit each of the following URLs and enter some data:')
print('\n'.join(user_entry_urls))
input('Press Enter when complete')

# Request the model be fit

print('Enqueuing model fitting task')
req = requests.request(
    'POST',
    url + '/' + collection_id + '/enqueue',
    json={
        'collection_private_key_secret': collection_private_key_secret
    }
)

# Retrieve the fit model

while True:
    print('Checking if model fitting is complete')
    req = requests.request(
        'POST',
        url + '/' + collection_id + '/status',
        json={
            'collection_private_key_secret': collection_private_key_secret
        }
    )
    resp = req.json()

    if resp['status'] == 'complete':
        break

model = pickle.loads(
    collection_public_key_client_private_key_box.decrypt(
        base64.urlsafe_b64decode(resp['result'])
    )
)
print('Received differentially private model:')
print('weight = ' + str(model.coef_[0]) + ' * height + ' + str(model.intercept_))
