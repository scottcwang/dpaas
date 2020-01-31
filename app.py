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
api.add_resource(TokenResource, '/<int:collection_id>/token/<string:action>')
api.add_resource(EntryResource, '/<int:collection_id>/entry/<string:token>', '/<int:collection_id>/submit')
api.add_resource(EnqueueResource, '/<int:collection_id>/enqueue/<string:token>')
api.add_resource(StatusResource, '/<int:collection_id>/status/<string:token>')