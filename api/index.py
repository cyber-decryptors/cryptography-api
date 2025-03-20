from flask import Flask, jsonify, request

app = Flask(__name__)

data = []

@app.route("/generate-key", methods=['POST'])
def generate_key():
    data.append(request.get_json())
    return '', 204

@app.route('/generate-key', methods=['GET'])
def get_user_data():
    return jsonify(data)