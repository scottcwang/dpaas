from flask import request
from flask_restful import Resource
from marshmallow import Schema, fields, ValidationError

from Model import *

import nacl.utils
import nacl.public

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization


class RootInputSchema(Schema):
    attributes = fields.List(fields.Str(), required=True)
    fit_model = fields.Str(required=True)
    attribute_y_index = fields.Int()
    fit_arguments = fields.Dict(
        keys=fields.Str(), values=fields.Raw(), required=True)
    description = fields.Str(required=True)
    public_key = fields.Str(required=True)
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

        # TODO instead of this, validate as certificate
        # cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        # public_key = cert.public_key()
        try:
            public_key = load_pem_public_key(
                data['public_key'].encode('utf-8'), backend=default_backend())
            public_key = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except:
            return 'Public key could not be parsed', 400
        # TODO Challenge ownership of public key

        # TODO refactor out
        if data['fit_model'] not in ['GaussianNB', 'LogisticRegression', 'LinearRegression', 'KMeans', 'PCA', 'StandardScaler']:
            return 'Fit model is not supported', 400

        # TODO check arguments are permissible for model
        # TODO check y-index allowed for model

        if data['attribute_y_index'] >= len(data['attributes']) or data['attribute_y_index'] < 0:
            return 'attribute_y_index invalid', 400

        entry_private_key = nacl.public.PrivateKey.generate()
        entry_public_key = entry_private_key.public_key

        collection = Collection(
            attributes=data['attributes'],
            attribute_y_index=data['attribute_y_index'],
            fit_model=data['fit_model'],
            fit_arguments=data['fit_arguments'],
            description=data['description'],
            response_start_time=data['response_start_time'],
            response_end_time=data['response_end_time'],
            public_key=public_key,
            entry_private_key=entry_private_key.encode(
                encoder=nacl.encoding.RawEncoder),
            entry_public_key=entry_public_key.encode(
                encoder=nacl.encoding.RawEncoder)
        )

        db.session.add(collection)
        db.session.commit()

        return collection.id, 201
