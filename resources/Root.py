from flask import request
from flask_restful import Resource
from flask_redis import FlaskRedis
from marshmallow import Schema, fields

from Model import *

import nacl.signing
import nacl.encoding
import nacl.public
import nacl.secret

import base64

redis_conn = FlaskRedis()


class RootInputSchema(Schema):
    attributes = fields.List(fields.Str(), required=True)
    fit_model = fields.Str(required=True)
    attribute_y_index = fields.Int()
    fit_arguments = fields.Dict(
        keys=fields.Str(), values=fields.Raw(), required=True)
    description = fields.Str(required=True)
    client_verify_key = fields.Str(required=True)
    response_start_time = fields.Float(required=True)
    response_end_time = fields.Float(required=True)


root_input_schema = RootInputSchema()


class RootResource(Resource):
    def post(self):
        json_data = request.get_json()
        if not json_data:
            return 'Request is not JSON', 400
        try:
            data = root_input_schema.load(json_data)
        except:
            return 'JSON payload does not conform to schema', 400

        # TODO validate public key online
        try:
            client_verify_key = nacl.signing.VerifyKey(
                data['client_verify_key'], nacl.encoding.URLSafeBase64Encoder)
        except:
            return 'Public key could not be parsed', 400

        # TODO refactor out
        if data['fit_model'] not in ['GaussianNB', 'LogisticRegression', 'LinearRegression', 'KMeans', 'PCA', 'StandardScaler']:
            return 'Fit model is not supported', 400

        # TODO check arguments are permissible for model
        # TODO check y-index allowed for model

        if data['attribute_y_index'] >= len(data['attributes']) or data['attribute_y_index'] < 0:
            return 'attribute_y_index invalid', 400

        collection_private_key_secret = secrets.token_bytes(
            nacl.secret.SecretBox.KEY_SIZE)
        collection_private_key = nacl.public.PrivateKey.generate()
        collection_private_key_encrypted = nacl.secret.SecretBox(
            collection_private_key_secret).encrypt(bytes(collection_private_key))
        collection_public_key = collection_private_key.public_key

        collection = Collection(
            attributes=data['attributes'],
            attribute_y_index=data['attribute_y_index'],
            fit_model=data['fit_model'],
            fit_arguments=data['fit_arguments'],
            description=data['description'],
            response_start_time=datetime.datetime.fromtimestamp(
                data['response_start_time'], datetime.timezone.utc),
            response_end_time=datetime.datetime.fromtimestamp(
                data['response_end_time'], datetime.timezone.utc),
            client_verify_key=client_verify_key.encode(),
            collection_private_key=bytes(collection_private_key_encrypted),
            collection_public_key=collection_public_key.encode()
        )

        db.session.add(collection)
        db.session.commit()

        client_public_key = client_verify_key.to_curve25519_public_key()
        collection_private_key_box = nacl.public.Box(
            collection_private_key, client_public_key)
        collection_private_key_secret_encrypted = collection_private_key_box.encrypt(
            collection_private_key_secret)

        return_value = {
            'id': collection.id,
            'public_key_b64': base64.urlsafe_b64encode(
                collection_public_key.encode()).decode(),
            'private_key_secret': base64.urlsafe_b64encode(
                collection_private_key_secret_encrypted).decode()
        }

        return return_value, 201
