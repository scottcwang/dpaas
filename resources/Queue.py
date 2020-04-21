from flask import request, render_template, make_response
from flask_restful import Resource

from Model import db, Collection, Entry, Status

from resources.Token import redis_conn

import nacl.public
from rq import Queue

import diffprivlib.models

import pickle

from config import REDIS_QUEUE_IS_ASYNC

q = Queue(connection=redis_conn, is_async=REDIS_QUEUE_IS_ASYNC)


def process(collection_id):
    collection = Collection.query.get(collection_id)
    if not collection:
        return
    collection.status = Status.running
    db.session.commit()

    attribute_x_indices = [index for index in range(
        len(collection.attributes)) if index != collection.attribute_y_index]
    collection_private_key = nacl.public.PrivateKey(
        collection.entry_private_key)
    sealed_box = nacl.public.SealedBox(collection_private_key)
    entries = Entry.query.filter_by(collection_id=collection.id).all()
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
    fit = model.fit(X, y)
    # dump pickled fit object into database
    collection.result = pickle.dumps(fit)
    collection.status = Status.complete
    db.session.add(collection)
    # Delete all entries
    for entry in Entry.query.filter_by(collection_id=collection.id).all():
        db.session.delete(entry)
    db.session.commit()


class EnqueueResource(Resource):
    def post(self, collection_id):
        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        if collection.status is not None:
            return 'Already enqueued', 400
        collection.status = Status.enqueued
        db.session.add(collection)
        db.session.commit()
        q.enqueue(process, collection_id)
        return None, 202
