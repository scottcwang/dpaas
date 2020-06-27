from flask import Flask
from marshmallow import Schema, fields, pre_load, validate
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy

import datetime
import secrets
from enum import Enum

ma = Marshmallow()
db = SQLAlchemy()


class Status(Enum):
    active = -1
    enqueued = 0
    running = 1
    complete = 2


class Collection(db.Model):
    id = db.Column(db.String, primary_key=True)

    attributes = db.Column(db.PickleType)  # list of strings
    # index of y-attribute in attributes (if any)
    attribute_y_index = db.Column(db.Integer)
    fit_model = db.Column(db.String, nullable=False)
    fit_arguments = db.Column(db.PickleType)  # dict of arguments to fit
    description = db.Column(db.String(1000), nullable=False)  # markdown
    response_start_time = db.Column(db.DateTime(timezone=True), nullable=False)
    response_end_time = db.Column(db.DateTime(timezone=True), nullable=False)

    client_verify_key = db.Column(db.LargeBinary(), nullable=False)

    collection_private_key = db.Column(db.LargeBinary(), nullable=False)
    collection_public_key = db.Column(db.LargeBinary(), nullable=False)

    result = db.Column(db.PickleType)
    status = db.Column(db.Enum(Status))

    def __init__(self, attributes, attribute_y_index, fit_model, fit_arguments, description, response_start_time, response_end_time, client_verify_key, collection_private_key, collection_public_key):
        self.id = secrets.token_urlsafe(16)
        self.attributes = attributes
        self.attribute_y_index = attribute_y_index
        self.fit_model = fit_model
        self.fit_arguments = fit_arguments
        self.description = description
        self.response_start_time = response_start_time
        self.response_end_time = response_end_time
        self.client_verify_key = client_verify_key
        self.collection_private_key = collection_private_key
        self.collection_public_key = collection_public_key
        self.status = Status.active


class Entry(db.Model):
    entry_serial = db.Column(db.String(), primary_key=True)
    collection_id = db.Column(db.String, db.ForeignKey('collection.id'))
    client_serial = db.Column(db.String())
    issued_at = db.Column(db.DateTime(timezone=True))
    session_token = db.Column(db.String())
    values = db.Column(db.LargeBinary())

    collection = db.relationship('Collection')

    def __init__(self, collection_id, client_serial):
        self.entry_serial = secrets.token_urlsafe(16)
        self.issued_at = datetime.datetime.now(datetime.timezone.utc)
        self.collection_id = collection_id
        self.client_serial = client_serial
