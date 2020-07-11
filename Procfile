web: gunicorn "run:create_app()"
redis: rq worker --url $REDIS_URL
