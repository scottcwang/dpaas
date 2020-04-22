from flask import render_template, make_response, request
from flask_restful import Resource

from Model import db, Collection, Entry

from flask_wtf import FlaskForm
from wtforms import FloatField, FieldList, HiddenField
from wtforms.validators import InputRequired

from datetime import datetime, timedelta
import secrets
import base64

import jwt
import nacl.utils
import nacl.public
import nacl.signing

from resources.Root import redis_conn


def create_form(attributes, session_token):
    class SubEntryForm(FlaskForm):
        pass
    SubEntryForm.session_token = HiddenField(
        'session_token', default=session_token)
    for attribute_index, (attribute_name, attribute_value) in enumerate(attributes):
        setattr(
            SubEntryForm,
            'field_' + str(attribute_index),
            FloatField(attribute_name, default=attribute_value,
                       validators=[InputRequired()])
        )
    return SubEntryForm


class EntryResource(Resource):
    # TODO change verb. This GET is state-changing
    def get(self, collection_id, voucher):
        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        if datetime.now() < collection.response_start_time or datetime.now() > collection.response_end_time:
            return 'Not within collection interval', 410
        try:
            verify_key = nacl.signing.VerifyKey(collection.public_key)
            voucher_contents = verify_key.verify(
                base64.urlsafe_b64decode(voucher.encode()))
        except Exception as e:
            return 'Voucher could not be verified', 400

        try:
            client_serial_str, entry_serial_str, issued_at_str, * \
                tail = voucher_contents.decode().split(',')
        except:
            return 'Voucher contains fewer than three values', 400

        if len(tail) > 0:
            return 'Voucher contains more than three values', 400

        client_serial = client_serial_str
        entry_serial = entry_serial_str
        try:
            issued_at = datetime.fromtimestamp(float(issued_at_str))
        except:
            return 'Timestamp invalid'

        entry = Entry.query.get(entry_serial)
        if not entry:
            return 'Entry does not exist', 404
        if entry.collection_id != collection.id:
            # TODO Leaks existence of entry serial
            return 'Entry serial not for this collection', 400
        if not entry.client_serial:
            return 'Voucher already redeemed for a form', 400
        if entry.client_serial != client_serial:
            return 'Voucher client serial does not match registration', 400

        if abs(entry.issued_at - issued_at) > timedelta(seconds=60):
            return 'Voucher not issued and registered at same time', 400

        entry.client_serial = None
        db.session.add(entry)
        db.session.commit()

        attributes = [(attribute, '')
                      for attribute in collection.attributes]
        session_token = secrets.token_urlsafe(16)
        # produce a submit session
        # TODO migrate to Entry table
        try:
            redis_conn.setex('submit:' + str(collection_id) +
                             ':' + str(session_token), 600, '')
        except:
            return 'Redis error', 500
        headers = {'Content-Type': 'text/html'}
        form_class = create_form(attributes, session_token)
        return make_response(render_template('entry.html', form=form_class(), attributes=attributes, collection=collection, entry_serial=entry_serial, session_token=session_token), 200, headers)

    def post(self, entry_serial):
        # recreate form schema for validation
        entry = Entry.query.get(entry_serial)
        if not entry:
            return 'Entry does not exist', 404
        collection = entry.collection
        form = create_form([(attribute, '')
                            for attribute in collection.attributes], '')()
        if not form.validate():
            return 'Form data does not conform to schema, or CSRF token does not match', 400

        # consume a submit session
        key = 'submit:' + str(collection.id) + ':' + form.session_token.data
        session_value = redis_conn.get(key).decode('utf-8')
        if session_value is None:  # no session exists
            return 'Session does not exist', 403
        redis_conn.delete(key)

        values = [getattr(form, 'field_' + str(attribute_index)
                          ).data for attribute_index in range(len(collection.attributes))]
        values_json_bytes = ','.join(map(str, values)).encode()
        entry_public_key = nacl.public.PublicKey(collection.entry_public_key)
        values_json_box = nacl.public.SealedBox(
            entry_public_key)
        values_json_encrypt = values_json_box.encrypt(values_json_bytes)
        entry.values = values_json_encrypt
        db.session.add(entry)
        db.session.commit()
        return None
