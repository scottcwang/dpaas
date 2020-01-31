from flask import Flask

def create_app(config_filename):
    app = Flask(__name__)

    app.config.from_object(config_filename)
    
    from app import api_bp
    app.register_blueprint(api_bp)

    from resources.Entry import redis_conn
    redis_conn.init_app(app)

    from Model import db
    db.init_app(app)

    from flaskext.markdown import Markdown
    Markdown(app)

    return app


if __name__ == "__main__":
    app = create_app("config")
    app.run(debug=True)