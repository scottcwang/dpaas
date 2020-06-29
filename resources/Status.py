from flask import request, render_template, make_response
from flask_restful import Resource
from marshmallow import Schema, fields

from Model import db, Collection, Status, Entry

import pickle
import base64

import nacl.public
import nacl.secret
import nacl.signing


class StatusInputSchema(Schema):
    collection_private_key_secret = fields.Str(required=True)


status_input_schema = StatusInputSchema()


class StatusResource(Resource):
    def post(self, collection_id):
        json_data = request.get_json()
        if not json_data:
            return 'Request is not JSON', 400
        try:
            data = status_input_schema.load(json_data)
        except:
            return 'JSON payload does not conform to schema', 400

        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404

        try:
            collection_private_key_decrypted = nacl.secret.SecretBox(
                data['collection_private_key_secret'],
                encoder=nacl.encoding.URLSafeBase64Encoder
            ).decrypt(collection.collection_private_key)
        except:
            return 'Incorrect collection private key secret', 400

        return_dict = {
            'status': collection.status.name,
            'response_count': collection.submit_count,
            'model': {
                'attributes': collection.attributes,
                'attribute_y_index': collection.attribute_y_index,
                'fit_model': collection.fit_model,
                'fit_arguments': collection.fit_arguments,
                'description': collection.description,
                'response_start_time': collection.response_start_time.timestamp(),
                'response_end_time': collection.response_end_time.timestamp()
            }
        }

        if collection.status == Status.complete:
            client_public_key = nacl.signing.VerifyKey(
                collection.client_verify_key).to_curve25519_public_key()
            collection_private_key = nacl.public.PrivateKey(
                collection_private_key_decrypted)
            collection_private_key_box = nacl.public.Box(
                collection_private_key, client_public_key)

            collection_result_encrypted = collection_private_key_box.encrypt(
                collection.result)

            return_dict['result'] = base64.urlsafe_b64encode(
                collection_result_encrypted).decode()
            # TODO when is the collection deleted?

        return return_dict, 200
