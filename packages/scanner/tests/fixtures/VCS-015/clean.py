import ast
import json
import subprocess

def deploy(branch):
    # Argument list — no shell interpretation
    subprocess.run(["git", "pull", "origin", branch], check=True)

def list_files(path):
    return subprocess.run(["ls", "-la", path], capture_output=True, check=True)

def parse_config(text):
    # Safe alternative to eval()
    return ast.literal_eval(text)

def parse_json(text):
    return json.loads(text)
