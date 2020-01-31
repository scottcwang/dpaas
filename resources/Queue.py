from flask import request, render_template, make_response
from flask_restful import Resource

from Model import db, Collection, Entry

from resources.Token import redis_conn, consume_collection_token

from rq import Queue

import diffprivlib.models

import pickle

from config import REDIS_QUEUE_IS_ASYNC

q = Queue(connection = redis_conn, is_async=REDIS_QUEUE_IS_ASYNC)

def process(collection_id):
    collection = Collection.query.get(collection_id)
    if not collection:
        return
    collection.status = 1
    db.session.commit()

    attribute_x_indices = [index for index in range(len(collection.attributes)) if index != collection.attribute_y_index]

    X, y = zip(*[
        (
            [entry.values[index] for index in attribute_x_indices],
            entry.values[collection.attribute_y_index]
        )
        for entry in Entry.query.filter_by(collection_id = collection.id).all()
    ])

    model = getattr(diffprivlib.models, collection.fit_model)(**collection.fit_arguments)
    fit = model.fit(X, y)
    # dump pickled fit object into database
    collection.result = pickle.dumps(fit)
    collection.status = 2
    db.session.add(collection)
    # Delete all entries
    for entry in Entry.query.filter_by(collection_id = collection.id).all():
        db.session.delete(entry)
    db.session.commit()

class EnqueueResource(Resource):
    def post(self, collection_id, token):
        consume_collection_token_result = consume_collection_token(collection_id, token, 'enqueue')
        if consume_collection_token_result[1] != 200:
            return consume_collection_token_result
        collection = consume_collection_token_result[0]
        if collection.status is not None:
            return 'Already enqueued', 400
        collection.status = 0
        db.session.add(collection)
        db.session.commit()
        q.enqueue(process, collection_id)
        return None, 202