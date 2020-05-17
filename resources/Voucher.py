from flask import request
from flask_restful import Resource
from Model import db, Collection, Entry

from datetime import datetime, timedelta
import secrets
import base64

import nacl.public
import nacl.signing


class VoucherResource(Resource):
    def post(self, collection_id):
        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        if datetime.now() < collection.response_start_time or datetime.now() > collection.response_end_time:
            return 'Not within collection interval', 410
        if not request.data:
            return 'No client serial number provided for voucher registration', 400
        box = nacl.public.Box(nacl.public.PrivateKey(
            collection.collection_private_key), nacl.signing.VerifyKey(collection.client_verify_key).to_curve25519_public_key())
        client_serial = base64.urlsafe_b64encode(
            box.decrypt(request.data)).decode()
        entry = Entry(collection_id, client_serial)
        db.session.add(entry)
        db.session.commit()
        return entry.entry_serial, 201
