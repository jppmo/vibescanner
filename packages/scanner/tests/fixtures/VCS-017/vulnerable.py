from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route("/download")
def download():
    return send_file(request.args.get("file"))

@app.route("/read")
def read_file():
    with open(request.args.get("path")) as f:
        return f.read()

@app.route("/save", methods=["POST"])
def save():
    target = os.path.join("/data", request.form.get("dest"))
    with open(target, "w") as f:
        f.write(request.json.get("content"))
    return "ok"

@app.route("/delete")
def delete_file():
    os.remove(request.args.get("file"))
    return "ok"
