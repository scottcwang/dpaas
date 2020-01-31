from flask import render_template, make_response, request
from flask_restful import Resource

from Model import db, Collection, Entry

from flask_wtf import FlaskForm
from wtforms import FloatField, FieldList, HiddenField
from wtforms.validators import InputRequired

from datetime import datetime, timedelta
import secrets
import jwt

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key, load_der_private_key
from cryptography.hazmat.primitives import serialization

from resources.Token import redis_conn, consume_collection_token

def create_form(attributes, session_token):
    class SubEntryForm(FlaskForm):
        pass
    SubEntryForm.session_token = HiddenField('session_token', default = session_token)
    for attribute_index, (attribute_name, attribute_value) in enumerate(attributes):
        setattr(
            SubEntryForm,
            'field_' + str(attribute_index),
            FloatField(attribute_name, default = attribute_value, validators=[InputRequired()])
        )
    return SubEntryForm

def validate_entry_token(collection_id, token):
    collection = Collection.query.get(collection_id)
    # TODO prevent if fit already enqueued or complete
    if not collection or datetime.now() < collection.response_start_time or datetime.now() > collection.response_end_time:
        return None
    try:
        jwt_payload = jwt.decode(token, verify=False)
    except:
        return None
    if 'sub' not in jwt_payload:
        return None
    entry = Entry.query.get(jwt_payload['sub'])
    if not entry or entry.collection_id != collection_id:
        return None
    # check whether token was signed by entry modification key (which only I have)
    private_key = load_der_private_key(entry.modification_key, password=None, backend=default_backend())
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        jwt.decode(token, pem_public_key, algorithms='RS256')
        # token signature is valid
        return entry
    except:
        return None

class EntryResource(Resource):
    def get(self, collection_id, token):
        session_token = secrets.token_urlsafe()
        entry = validate_entry_token(collection_id, token)
        if entry:
            collection = entry.collection
            attributes = list(zip(collection.attributes, entry.values))
            # produce a submit session
            try:
                redis_conn.setex('submit:' + str(collection_id) + ':' + str(session_token), 600, entry.id)
            except:
                return 'Redis error', 500
        else:
            consume_collection_token_result = consume_collection_token(collection_id, token, 'entry')
            if consume_collection_token_result[1] != 200:
                return consume_collection_token_result
            collection = consume_collection_token_result[0]
            attributes = [(attribute, '') for attribute in collection.attributes]
            # produce a submit session
            try:
                redis_conn.setex('submit:' + str(collection_id) + ':' + str(session_token), 600, '')
            except:
                return 'Redis error', 500
        headers = {'Content-Type': 'text/html'}
        form_class = create_form(attributes, session_token)
        return make_response(render_template('entry.html', form = form_class(), attributes = attributes, collection = collection, session_token = session_token), 200, headers)

    def post(self, collection_id):
        # recreate form schema for validation
        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        form = create_form([(attribute, '') for attribute in collection.attributes], '')()
        if not form.validate():
            return 'Form data does not conform to schema, or CSRF token does not match', 400
        
        # consume a submit session
        key = 'submit:' + str(collection_id) + ':' + form.session_token.data
        session_value = redis_conn.get(key).decode('utf-8')
        if session_value is None: # no session exists
            return 'Session does not exist', 403
        redis_conn.delete(key)

        values = [getattr(form, 'field_' + str(attribute_index)).data for attribute_index in range(len(collection.attributes))]
        if session_value == '': # new entry
            # generate modification key
            modification_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            modification_key_der = modification_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            entry = Entry(collection_id, modification_key_der, '', values)
            db.session.add(entry)
            db.session.commit()
            token = jwt.encode(
                { 'sub' : entry.id },
                modification_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ),
                algorithm='RS256'
            )
            entry.token = token
            token = token.decode('utf-8')
        else: # existing entry
            entry = Entry.query.get(session_value)
            entry.values = values
            token = entry.token
            db.session.add(entry)
            db.session.commit()
        # concat together page url for modification
        return request.host_url + str(collection_id) + '/entry/' + token