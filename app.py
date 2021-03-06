from flask import Blueprint
from flask_restful import Api

from resources.Root import RootResource
from resources.Voucher import VoucherResource
from resources.Entry import EntryResource
from resources.Submit import SubmitResource
from resources.Enqueue import EnqueueResource
from resources.Status import StatusResource

api_bp = Blueprint('api', __name__)
api = Api(api_bp)

api.add_resource(RootResource, '/')
api.add_resource(VoucherResource, '/<string:collection_id>/voucher')
api.add_resource(EntryResource, '/entry/<string:voucher>')
api.add_resource(SubmitResource, '/submit/<string:entry_serial>')
api.add_resource(
    EnqueueResource, '/<string:collection_id>/enqueue')
api.add_resource(StatusResource, '/<string:collection_id>/status')
