from flask import Flask


def create_app():
    return_app = Flask(__name__)

    return_app.config.from_envvar('DPAAS_CONFIG_PATH')

    from app import api_bp
    return_app.register_blueprint(api_bp)

    from resources.Enqueue import redis_conn
    redis_conn.init_app(return_app)

    from Model import db
    db.init_app(return_app)

    from flaskext.markdown import Markdown
    Markdown(return_app)

    return return_app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
