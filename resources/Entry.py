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
    def get(self, collection_id, token):
        session_token = secrets.token_urlsafe()
        consume_collection_token_result = consume_collection_token(
            collection_id, token, 'entry')
        if consume_collection_token_result[1] != 200:
            return consume_collection_token_result
        collection = consume_collection_token_result[0]
        attributes = [(attribute, '')
                      for attribute in collection.attributes]
        # produce a submit session
        try:
            redis_conn.setex('submit:' + str(collection_id) +
                             ':' + str(session_token), 600, '')
        except:
            return 'Redis error', 500
        headers = {'Content-Type': 'text/html'}
        form_class = create_form(attributes, session_token)
        return make_response(render_template('entry.html', form=form_class(), attributes=attributes, collection=collection, session_token=session_token), 200, headers)

    def post(self, collection_id):
        # recreate form schema for validation
        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        form = create_form([(attribute, '')
                            for attribute in collection.attributes], '')()
        if not form.validate():
            return 'Form data does not conform to schema, or CSRF token does not match', 400

        # consume a submit session
        key = 'submit:' + str(collection_id) + ':' + form.session_token.data
        session_value = redis_conn.get(key).decode('utf-8')
        if session_value is None:  # no session exists
            return 'Session does not exist', 403
        redis_conn.delete(key)

        values = [getattr(form, 'field_' + str(attribute_index)
                          ).data for attribute_index in range(len(collection.attributes))]
        entry = Entry(collection_id, values)
        db.session.add(entry)
        db.session.commit()
        return None
