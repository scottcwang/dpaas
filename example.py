#!/usr/bin/env python3

import base64
import datetime
import secrets
import pickle

import requests

from nacl.signing import SigningKey
from nacl.public import PublicKey, Box

url = 'http://127.0.0.1:5000'

# Create a collection

signing_key = SigningKey.generate()

requests.request(
    'POST',
    url + '/',
    json={
        'attributes': ['Height / cm', 'Weight / kg'],
        'fit_model': 'LinearRegression',
        'attribute_y_index': 1,
        'fit_arguments': {
            'epsilon': 1
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

req = requests.request(
    'POST',
    url + '/',
    json={
        'attributes': ['Height / cm', 'Weight / kg'],
        'fit_model': 'LinearRegression',
        'attribute_y_index': 1,
        'fit_arguments': {
            'epsilon': 1
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

# Register a voucher client serial, which will be used to redeem an entry form

client_serial = secrets.token_urlsafe()
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

timestamp = datetime.datetime.now().timestamp()

voucher = base64.urlsafe_b64encode(
    signing_key.sign(
        (client_serial + ',' + entry_serial + ',' + str(timestamp)).encode()
    )
).decode()

# Give this link to the user:
user_entry_url = url + '/entry/' + voucher

# Request the model be fit

req = requests.request(
    'POST',
    url + '/' + collection_id + '/enqueue',
    json={
        'collection_private_key_secret': collection_private_key_secret
    }
)

# Retrieve the fit model

req = requests.request(
    'POST',
    url + '/' + collection_id + '/status',
    json={
        'collection_private_key_secret': collection_private_key_secret
    }
)

resp = req.json()

model = pickle.loads(
    collection_public_key_client_private_key_box.decrypt(
        base64.urlsafe_b64decode(resp['result'])
    )
)
