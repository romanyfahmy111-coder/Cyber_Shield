"""PhishLens application factory."""
import os

from flask import Flask

from config import Config


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)

    if app.config.get("ON_VERCEL"):
        # Behind Vercel's proxy: trust X-Forwarded-* so the real client IP
        # (rate limiting) and the https host (same-origin check) are correct.
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db_path = app.config["DATABASE"]
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

    from .database import models

    models.init_db(db_path)

    from .security import init_security

    init_security(app)

    from .routes import bp

    app.register_blueprint(bp)
    return app
