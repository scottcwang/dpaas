from flask import request, render_template, make_response
from flask_restful import Resource

from Model import db, Collection, Status

from resources.Token import consume_collection_token


class StatusResource(Resource):
    def get(self, collection_id, token):
        consume_collection_token_result = consume_collection_token(
            collection_id, token, 'status')
        if consume_collection_token_result[1] != 200:
            return consume_collection_token_result
        collection = consume_collection_token_result[0]
        if collection.status == Status.complete:  # complete; return the pickled fit object
            headers = {'Content-Type': 'application/octet-stream'}
            return make_response(collection.result, 200, headers)
            # TODO when is the collection deleted?
        elif collection.status == Status.running:
            return 'Running', 202
        elif collection.status == Status.enqueued:
            return 'Enqueued', 202
        else:
            return None, 204
