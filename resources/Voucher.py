import datetime

from flask import request
from flask_restful import Resource
from marshmallow import Schema, fields

import nacl.public
import nacl.signing

from Model import db, Collection, Entry


class VoucherInputSchema(Schema):
    collection_private_key_secret = fields.Str(required=True)
    client_serial_encrypt = fields.Str(required=True)


voucher_input_schema = VoucherInputSchema()


class VoucherResource(Resource):
    def post(self, collection_id):
        json_data = request.get_json()
        if not json_data:
            return 'Request is not JSON', 400
        try:
            data = voucher_input_schema.load(json_data)
        except:
            return 'JSON payload does not conform to schema', 400

        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        if datetime.datetime.now(datetime.timezone.utc) < collection.response_start_time or datetime.datetime.now(datetime.timezone.utc) > collection.response_end_time:
            return 'Not within collection interval', 410
        if collection.status.value >= 0:
            return 'Already enqueued', 400
        try:
            collection_private_key_decrypted = nacl.secret.SecretBox(
                data['collection_private_key_secret'],
                encoder=nacl.encoding.URLSafeBase64Encoder
            ).decrypt(collection.collection_private_key)
        except:
            return 'Incorrect collection private key secret', 400

        box = nacl.public.Box(
            nacl.public.PrivateKey(collection_private_key_decrypted),
            nacl.signing.VerifyKey(
                collection.client_verify_key).to_curve25519_public_key()
        )

        client_serial = box.decrypt(
            data['client_serial_encrypt'],
            encoder=nacl.encoding.URLSafeBase64Encoder
        ).decode()

        if Entry.query.filter_by(collection_id=collection_id, client_serial=client_serial).count() != 0:
            return 'Client serial already used', 400

        entry = Entry(collection_id, client_serial)
        db.session.add(entry)
        db.session.commit()

        return_value = {
            'entry_serial': entry.entry_serial
        }

        return return_value, 201
