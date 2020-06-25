from flask import request, render_template, make_response
from flask_restful import Resource

from Model import db, Collection, Status


class StatusResource(Resource):
    def get(self, collection_id):
        collection = Collection.query.get(collection_id)
        if not collection:
            return 'Collection ID not found', 404
        if collection.status == Status.complete:  # complete; return the pickled fit object
            headers = {'Content-Type': 'application/octet-stream'}
            return make_response(collection.result, 200, headers)
            # TODO when is the collection deleted?
        elif collection.status == Status.running:
            return 'Running', 202
        elif collection.status == Status.enqueued:
            return 'Enqueued', 202
        else:
            # TODO return entry count
            return None, 204
