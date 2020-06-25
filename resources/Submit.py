from flask_restful import Resource

from Model import db, Collection, Entry
from resources.Entry import create_form

import datetime

import nacl.public


class SubmitResource(Resource):
    def post(self, entry_serial):
        # recreate form schema for validation
        entry = Entry.query.get(entry_serial)
        if not entry:
            return 'Entry does not exist', 404
        if entry.values is not None:
            return 'Form already submitted', 400

        collection = entry.collection
        form = create_form([(attribute, '')
                            for attribute in collection.attributes], '')()
        if not form.validate():
            return 'Form data does not conform to schema, or CSRF token does not match', 400

        if datetime.datetime.now(datetime.timezone.utc) < collection.response_start_time or datetime.datetime.now(datetime.timezone.utc) > collection.response_end_time:
            return 'Not within collection interval', 410
        if collection.status is not None:
            return 'Already enqueued', 400

        if entry.session_token != form.session_token.data:
            return 'Incorrect session token', 403
        entry.session_token = None

        values = [getattr(form, 'field_' + str(attribute_index)
                          ).data for attribute_index in range(len(collection.attributes))]
        values_json_bytes = ','.join(map(str, values)).encode()
        collection_public_key = nacl.public.PublicKey(
            collection.collection_public_key)
        values_json_box = nacl.public.SealedBox(
            collection_public_key)
        values_json_encrypt = values_json_box.encrypt(values_json_bytes)
        entry.values = values_json_encrypt
        db.session.add(entry)
        db.session.commit()
        return None
