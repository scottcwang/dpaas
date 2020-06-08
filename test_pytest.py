import pytest
import docker
from dotenv import load_dotenv

from run import create_app


@pytest.fixture
def client():
    load_dotenv(dotenv_path='./.flaskenv')
    app = create_app()
    app.testing = True

    docker_client = docker.from_env()

    postgres_pulled = False
    try:
        docker_client.images.get("postgres:latest")
    except:
        docker_client.images.pull("postgres:latest")
        postgres_pulled = True
    postgres_container = docker_client.containers.run(
        "postgres:latest",
        ports={"5432/tcp": None},
        detach=True,
        remove=True,
        environment=["POSTGRES_HOST_AUTH_METHOD=trust"]
    )
    postgres_container.reload()
    postgres_port = postgres_container.ports["5432/tcp"][0]["HostPort"]
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgres://127.0.0.1:" + postgres_port

    redis_pulled = False
    try:
        docker_client.images.get("redis:latest")
    except:
        docker_client.images.pull("redis:latest")
        redis_pulled = True
    redis_container = docker_client.containers.run(
        "redis:latest",
        ports={"6379/tcp": None},
        detach=True,
        remove=True
    )
    redis_container.reload()
    redis_port = redis_container.ports["6379/tcp"][0]["HostPort"]
    app.config["REDIS_URL"] = "redis://127.0.0.1:" + redis_port

    c = app.test_client()

    with app.test_client() as client:
        yield client

    postgres_container.stop()
    if postgres_pulled:
        docker_client.images.remove("postgres")
    redis_container.stop()
    if redis_pulled:
        docker_client.images.remove("redis")


def test_root(client):
    r = client.post('/', data='a')
    assert r.status_code == 400 and r.json == 'Request is not JSON'
