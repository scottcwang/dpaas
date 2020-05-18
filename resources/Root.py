from flask import request
from flask_restful import Resource
from flask_redis import FlaskRedis
from marshmallow import Schema, fields, ValidationError

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
    response_start_time = fields.DateTime(required=True)
    response_end_time = fields.DateTime(required=True)


root_input_schema = RootInputSchema()


class RootResource(Resource):
    def post(self):
        json_data = request.get_json()
        if not json_data:
            return 'Request is not JSON', 400
        try:
            data = root_input_schema.load(json_data)
        except ValidationError as error:
            return 'JSON payload does not conform to schema', 400

        # TODO validate public key online
        try:
            client_verify_key = nacl.signing.VerifyKey(
                data['client_verify_key'], nacl.encoding.URLSafeBase64Encoder)
        except Exception as e:
            return 'Public key could not be parsed', 400
        # TODO Challenge ownership of public key

        # TODO refactor out
        if data['fit_model'] not in ['GaussianNB', 'LogisticRegression', 'LinearRegression', 'KMeans', 'PCA', 'StandardScaler']:
            return 'Fit model is not supported', 400

        # TODO check arguments are permissible for model
        # TODO check y-index allowed for model

        if data['attribute_y_index'] >= len(data['attributes']) or data['attribute_y_index'] < 0:
            return 'attribute_y_index invalid', 400

        collection_private_key_secret = secrets.token_bytes(
            nacl.secret.SecretBox.KEY_SIZE)
        collection_private_key_decrypted = nacl.public.PrivateKey.generate()
        collection_private_key = nacl.secret.SecretBox(
            collection_private_key_secret).encrypt(bytes(collection_private_key_decrypted))
        collection_public_key = collection_private_key_decrypted.public_key

        collection = Collection(
            attributes=data['attributes'],
            attribute_y_index=data['attribute_y_index'],
            fit_model=data['fit_model'],
            fit_arguments=data['fit_arguments'],
            description=data['description'],
            response_start_time=data['response_start_time'],
            response_end_time=data['response_end_time'],
            client_verify_key=client_verify_key.encode(),
            collection_private_key=bytes(collection_private_key),
            collection_public_key=collection_public_key.encode()
        )

        db.session.add(collection)
        db.session.commit()

        # TODO place collection_private_key_secret in Box
        return_value = ','.join([
            str(collection.id),
            base64.urlsafe_b64encode(collection_public_key.encode()).decode(),
            base64.urlsafe_b64encode(collection_private_key_secret).decode()
        ])

        return return_value, 201
