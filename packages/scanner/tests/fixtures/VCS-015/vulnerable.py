import os
import subprocess

def deploy(branch):
    subprocess.run(f"git pull origin {branch}", shell=True)

def list_files(path):
    return os.system(f"ls -la {path}")

def run_pipe(cmd):
    return os.popen(cmd).read()

def parse_config(text):
    return eval(text)

def execute_block(code):
    exec(code)
