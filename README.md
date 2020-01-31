# Differential privacy as a service

This is a Python web server that allows a client to configure a data collection task, collects possibly confidential numeric data from users, and [trains a differentially private model](https://diffprivlib.readthedocs.io/en/latest/) with the data.

The API is defined in [openapi.yaml](https://github.com/scottcwang/dpaas/openapi.yaml).
