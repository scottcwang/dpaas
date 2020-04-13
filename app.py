from flask import Blueprint
from flask_restful import Api

from resources.Root import RootResource
from resources.Token import TokenResource
from resources.Entry import EntryResource
from resources.Queue import EnqueueResource
from resources.Status import StatusResource

api_bp = Blueprint('api', __name__)
api = Api(api_bp)

api.add_resource(RootResource, '/')
api.add_resource(
    TokenResource, '/<string:collection_id>/token/<string:action>')
api.add_resource(EntryResource, '/<string:collection_id>/entry/<string:token>',
                 '/<string:collection_id>/submit')
api.add_resource(
    EnqueueResource, '/<string:collection_id>/enqueue/<string:token>')
api.add_resource(
    StatusResource, '/<string:collection_id>/status/<string:token>')
