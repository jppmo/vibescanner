from flask import Flask, request, send_from_directory
import os
import uuid

app = Flask(__name__)
BASE = "/data"

@app.route("/download/<file_id>")
def download(file_id):
    # Look up the real path by opaque ID — never trust user-supplied paths
    record = db.lookup(file_id)
    if not record:
        return "not found", 404
    return send_from_directory(BASE, record.filename)

@app.route("/upload", methods=["POST"])
def upload():
    new_name = f"{uuid.uuid4()}.bin"
    target = os.path.join(BASE, new_name)
    with open(target, "wb") as f:
        f.write(request.data)
    return new_name
