from flask import request
from flask_restful import Resource
from flask_redis import FlaskRedis
from Model import db, Collection, Entry

from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives import serialization

import jwt

redis_conn = FlaskRedis()


def consume_collection_token(collection_id, token, action):
    collection = Collection.query.get(collection_id)
    if not collection:
        return 'Collection ID not found', 404
    # TODO prevent if fit already enqueued or complete
    if action == 'entry' and (datetime.now() < collection.response_start_time or datetime.now() > collection.response_end_time):
        return 'Not within collection interval', 410
    public_key = load_der_public_key(
        collection.public_key, backend=default_backend())
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    try:
        # was the token signed by the client, and contains an authorised value?
        jwt_payload = jwt.decode(token, pem_public_key)
    except:
        return 'Token could not be decoded', 400
    # yes, the token was signed by the client
    if action == 'entry' and 'jti' not in jwt_payload:
        return 'Token does not contain nonce', 400
    if action != 'entry' and 'jti' in jwt_payload:
        return 'Token contains nonce for non-entry action', 400
    if 'iat' not in jwt_payload:
        return 'Token does not contain issuance time', 400
    key = action + ':' + \
        str(collection_id) + \
        ((':' + str(jwt_payload['jti'])) if action == 'entry' else '')
    value = redis_conn.get(key)
    if not value:
        return 'A corresponding session was not found', 403
    # was the token issued at the same time as it was requested?
    if abs(datetime.fromtimestamp(float(redis_conn.get(key))) - datetime.fromtimestamp(jwt_payload['iat'])) > timedelta(seconds=10):
        return 'Token not issued at same time as session request', 403
    redis_conn.delete(key)
    return collection, 200


class TokenResource(Resource):
    def post(self, collection_id, action):
        if action not in ['entry', 'enqueue', 'status']:
            return 'Unknown action', 400
        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        if action == 'entry' and (datetime.now() < collection.response_start_time or datetime.now() > collection.response_end_time):
            return 'Not within collection interval', 410
        if action == 'entry':
            if not request.data:
                return 'No nonce provided for entry action', 400
            nonce = request.data.decode('utf-8')
        else:
            nonce = None
        try:
            redis_conn.setex(
                action + ':' + str(collection_id) +
                ((':' + str(nonce)) if nonce else ''),
                600,
                datetime.now().timestamp()
            )
            return None, 201
        except:
            return 'Redis error', 500
