# Differential privacy as a service

This is a Python web server that allows a client to configure a data collection task, collects possibly confidential numeric data from users, and [trains a differentially private model](https://diffprivlib.readthedocs.io/en/latest/) with the data.

## Run the server

First, create an `.env` file in this directory with the following variables:
- `SQLALCHEMY_DATABASE_URI`
- `REDIS_URL`

Then, run:

```
pip install -r requirements.txt
rm -rf ./migrations
export DPAAS_CONFIG_PATH="config.py"
python migrate.py db init
python migrate.py db migrate
python migrate.py db upgrade
flask run
rq worker --url $REDIS_URL
```

## API

See [example.py](https://github.com/scottcwang/dpaas/blob/master/example.py) for how to create collections, register voucher client serials, request model fitting, and retrieve fit models.

The API definition, as OpenAPI 3.0, is in [openapi.yaml](https://github.com/scottcwang/dpaas/blob/master/openapi.yaml).

The test cases are in [test_pytest.py](https://github.com/scottcwang/dpaas/blob/master/test_pytest.py); they require Docker be installed in which to run PostgreSQL and Redis.
