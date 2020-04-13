from flask import Flask
from marshmallow import Schema, fields, pre_load, validate
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy

from datetime import datetime

from enum import Enum

ma = Marshmallow()
db = SQLAlchemy()


class Status(Enum):
    enqueued = 0
    running = 1
    complete = 2


class Collection(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    attributes = db.Column(db.PickleType)  # list of strings
    # index of y-attribute in attributes (if any)
    attribute_y_index = db.Column(db.Integer)
    fit_model = db.Column(db.String, nullable=False)
    fit_arguments = db.Column(db.PickleType)  # dict of arguments to fit
    description = db.Column(db.String(1000), nullable=False)  # markdown
    response_start_time = db.Column(db.TIMESTAMP, nullable=False)
    response_end_time = db.Column(db.TIMESTAMP, nullable=False)

    public_key = db.Column(db.LargeBinary(), nullable=False)

    entry_private_key = db.Column(db.LargeBinary(), nullable=False)
    entry_public_key = db.Column(db.LargeBinary(), nullable=False)

    result = db.Column(db.PickleType)
    status = db.Column(db.Enum(Status))

    def __init__(self, attributes, attribute_y_index, fit_model, fit_arguments, description, response_start_time, response_end_time, public_key, entry_private_key, entry_public_key):
        self.attributes = attributes
        self.attribute_y_index = attribute_y_index
        self.fit_model = fit_model
        self.fit_arguments = fit_arguments
        self.description = description
        self.response_start_time = response_start_time
        self.response_end_time = response_end_time
        self.public_key = public_key
        self.entry_private_key = entry_private_key
        self.entry_public_key = entry_public_key


class Entry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    collection_id = db.Column(db.Integer, db.ForeignKey('collection.id'))
    values = db.Column(db.PickleType)  # list of floats

    collection = db.relationship('Collection')

    def __init__(self, collection_id, values):
        self.collection_id = collection_id
        self.values = values
