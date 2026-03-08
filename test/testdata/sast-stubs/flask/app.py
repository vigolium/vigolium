from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/users", methods=["GET"])
def list_users():
    q = request.args.get("q", "")
    page = request.args.get("page", "1")
    return jsonify({"users": [], "q": q, "page": page})


@app.route("/users", methods=["POST"])
def create_user():
    name = request.form.get("name")
    email = request.json.get("email")
    return jsonify({"name": name, "email": email})


@app.route("/users/<int:user_id>")
def get_user(user_id):
    return jsonify({"id": user_id})


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/upload")
def upload():
    data = request.values.get("file")
    return jsonify({"uploaded": True})


@app.delete("/users/<int:user_id>")
def delete_user(user_id):
    return jsonify({"deleted": user_id})


app.add_url_rule("/status", "status", lambda: jsonify({"ok": True}))
