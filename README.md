# Differential privacy as a service

This is a Python web server that allows a client to configure a data collection task, collects possibly confidential numeric data from users, and [trains a differentially private model](https://diffprivlib.readthedocs.io/en/latest/) with the data.

The API definition, as OpenAPI 3.0, is in [openapi.yaml](https://github.com/scottcwang/dpaas/blob/master/openapi.yaml).

First, create an `.env` file in this directory with the following variables:
- `SQLALCHEMY_DATABASE_URI`
- `REDIS_URL`
Then, run:

```
pip install -r requirements.txt
rm -rf ./migrations
python migrate.py db init
python migrate.py db migrate
python migrate.py db upgrade
flask run
```

The test cases are in [test.py](https://github.com/scottcwang/dpaas/blob/master/test.py) and can be run in a separate session.
