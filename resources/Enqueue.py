from flask import request, render_template, make_response
from flask_restful import Resource
from marshmallow import Schema, fields

from Model import db, Collection, Entry, Status

from resources.Root import redis_conn

import nacl.public
import nacl.secret
from rq import Queue

import diffprivlib.models

import pickle

q = Queue(connection=redis_conn)


def process(collection_id, collection_private_key_decrypted):
    # TODO Handle exceptions
    collection = Collection.query.get(collection_id)
    if not collection:
        return
    collection.status = Status.running
    db.session.commit()

    attribute_x_indices = [index for index in range(
        len(collection.attributes)) if index != collection.attribute_y_index]
    sealed_box = nacl.public.SealedBox(
        nacl.public.PrivateKey(collection_private_key_decrypted))
    entries = Entry.query.filter(
        Entry.collection_id == collection.id, Entry.values != None).all()
    entries_decrypt = [sealed_box.decrypt(entry.values) for entry in entries]
    entries_decode = [bytes.decode(entry_decrypt).split(
        ',') for entry_decrypt in entries_decrypt]
    entries_float = [list(map(
        float, entry_decode)) for entry_decode in entries_decode]

    X, y = zip(*[(
        [entry_float[index] for index in attribute_x_indices],
        entry_float[collection.attribute_y_index])
        for entry_float in entries_float]
    )

    model = getattr(diffprivlib.models, collection.fit_model)(
        **collection.fit_arguments)
    model.fit(X, y)
    # TODO Handle timeout
    # TODO Handle PrivacyLeakWarning
    # dump pickled fit object into database
    collection.result = pickle.dumps(model)
    collection.status = Status.complete
    db.session.add(collection)
    # Delete all entries
    for entry in Entry.query.filter_by(collection_id=collection.id).all():
        db.session.delete(entry)
    db.session.commit()


class QueueInputSchema(Schema):
    collection_private_key_secret = fields.Str(required=True)


queue_input_schema = QueueInputSchema()


class EnqueueResource(Resource):
    def post(self, collection_id):
        json_data = request.get_json()
        if not json_data:
            return 'Request is not JSON', 400
        try:
            data = queue_input_schema.load(json_data)
        except:
            return 'JSON payload does not conform to schema', 400

        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        if collection.status.value >= 0:
            return 'Already enqueued', 400
        try:
            collection_private_key_decrypted = nacl.secret.SecretBox(
                data['collection_private_key_secret'], encoder=nacl.encoding.URLSafeBase64Encoder).decrypt(collection.collection_private_key)
        except:
            return 'Incorrect collection private key secret', 400

        collection.status = Status.enqueued
        db.session.add(collection)
        db.session.commit()
        q.enqueue(process, collection_id, collection_private_key_decrypted)
        return None, 202
