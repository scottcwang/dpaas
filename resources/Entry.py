from flask import render_template, make_response
from flask_restful import Resource

from Model import db, Collection, Entry

from flask_wtf import FlaskForm
from wtforms import FloatField, FieldList, HiddenField
from wtforms.validators import InputRequired

import datetime
import secrets
import base64

import nacl.signing
import nacl.bindings


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
    # To read voucher from path, must be GET (despite being state-changing)
    def get(self, voucher):
        voucher_bytes = base64.urlsafe_b64decode(
            voucher.encode())
        voucher_contents = voucher_bytes[nacl.bindings.crypto_sign_BYTES:]

        try:
            client_serial, entry_serial, issued_at_str, * \
                tail = voucher_contents.decode().split(',')
        except:
            return 'Voucher contains fewer than three values', 400

        if len(tail) > 0:
            return 'Voucher contains more than three values', 400

        try:
            issued_at = datetime.datetime.fromtimestamp(
                float(issued_at_str), datetime.timezone.utc)
        except:
            return 'Timestamp invalid', 400

        entry = Entry.query.get(entry_serial)
        if not entry:
            return 'Entry does not exist', 404
        if not entry.client_serial:
            return 'Voucher already redeemed for a form', 400
        if entry.client_serial != client_serial:
            return 'Voucher client serial does not match registration', 400

        if abs(entry.issued_at - issued_at) > datetime.timedelta(seconds=60):
            return 'Voucher not issued and registered at same time', 400

        collection = entry.collection
        if datetime.datetime.now(datetime.timezone.utc) < collection.response_start_time or datetime.datetime.now(datetime.timezone.utc) > collection.response_end_time:
            return 'Not within collection interval', 410
        if collection.status.value >= 0:
            return 'Already enqueued', 400
        try:
            verify_key = nacl.signing.VerifyKey(collection.client_verify_key)
            voucher_contents = verify_key.verify(voucher_bytes)
        except:
            return 'Voucher could not be verified', 400

        entry.client_serial = None

        attributes = [(attribute, '')
                      for attribute in collection.attributes]
        entry.session_token = secrets.token_urlsafe(16)
        db.session.add(entry)
        db.session.commit()

        headers = {'Content-Type': 'text/html'}
        form_class = create_form(attributes, entry.session_token)
        return make_response(render_template('entry.html', form=form_class(), attributes=attributes, collection=collection, entry_serial=entry_serial), 200, headers)
