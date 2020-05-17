# Differential privacy as a service

This is a Python web server that allows a client to configure a data collection task, collects possibly confidential numeric data from users, and [trains a differentially private model](https://diffprivlib.readthedocs.io/en/latest/) with the data.

The API definition, as OpenAPI 3.0, is in [openapi.yaml](https://github.com/scottcwang/dpaas/blob/master/openapi.yaml).

First, update [config.py](https://github.com/scottcwang/dpaas/blob/master/config.py) with the URLs to your PostgreSQL and Redis instances. Then, run:

```
pip install -r requirements.txt
rm -rf ./migrations
DPAAS_CONFIG_PATH='config.py'
FLASK_APP='run.py'
python migrate.py db init
python migrate.py db migrate
python migrate.py db upgrade
flask run
```

The test cases are in [test.py](https://github.com/scottcwang/dpaas/blob/master/test.py) and can be run in a separate session.
