from flask import Flask, Response, request, send_from_directory


app = Flask(__name__)

@app.route('/<path:path>')
def send_resources(path):
    return send_from_directory('public/', path)
@app.route('/')
def send_resources(path):
    return send_from_directory('public/', "index.html")

if __name__ == "__main__":
    app.run("0.0.0.0",8000)
