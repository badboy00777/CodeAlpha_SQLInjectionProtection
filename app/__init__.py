import os

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from app.config import load_dotenv


def create_app():
    load_dotenv()
    app = Flask(__name__)

    from app.routes import bp
    app.register_blueprint(bp)

    
    if os.environ.get("ALLOW_VULNERABLE_DEMO") == "1" and os.environ.get("FLASK_ENV") == "development":
        from app.vulnerable_demo import vuln
        app.register_blueprint(vuln)
        print("WARNING: VULNERABLE DEMO ENABLED - LOCAL USE ONLY")

    @app.errorhandler(Exception)
    def _any_error(exc):
        if isinstance(exc, HTTPException):
            return jsonify({"error": exc.description}), exc.code
        return jsonify({"error": "Server error"}), 500   # never leak SQL or stack traces

    return app