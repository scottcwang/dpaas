from flask import Flask


def create_app():
    app = Flask(__name__)

    app.config.from_envvar('DPAAS_CONFIG_PATH')

    from app import api_bp
    app.register_blueprint(api_bp)

    from resources.Enqueue import redis_conn
    redis_conn.init_app(app)

    from Model import db
    db.init_app(app)

    from flaskext.markdown import Markdown
    Markdown(app)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
