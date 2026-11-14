from flask import Blueprint, jsonify, render_template, request

from app import services
from app.services import ServiceError

bp = Blueprint("main", __name__)


def _token():
    return request.headers.get("X-Capability", "").strip()


@bp.errorhandler(ServiceError)
def _service_error(exc):
    return jsonify({"error": exc.message}), exc.status


@bp.get("/")
def index():
    return render_template("index.html")


@bp.post("/api/register")
def register():
    return jsonify(services.register_user(request.get_json(silent=True))), 201


@bp.post("/api/login")
def login():
    return jsonify(services.login_user(request.get_json(silent=True), request.remote_addr or "unknown"))


@bp.post("/api/capability")
def capability():
    data = request.get_json(silent=True)
    scope = data.get("scope") if isinstance(data, dict) else None
    return jsonify(services.issue_scope_token(_token(), scope))


@bp.get("/api/profile")
def profile():
    return jsonify(services.get_profile(_token()))


@bp.get("/api/notes")
def notes_list():
    return jsonify(services.list_notes(_token()))


@bp.post("/api/notes")
def notes_add():
    return jsonify(services.add_note(_token(), request.get_json(silent=True))), 201