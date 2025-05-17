from flask import Flask, request, jsonify
from google_api_checker import check_url_safety, get_page_title
import json
import os
from datetime import datetime

app = Flask(__name__)
HISTORY_FILE = "history.json"

def log_check(data):
    log_entry = {
        "url": data.get("url"),
        "is_safe": data.get("is_safe"),
        "threat_types": data.get("threat_types", []),
        "message": data.get("message"),
        "reputation_score": data.get("reputation_score"),
        "page_title": data.get("page_title"),
        "timestamp": datetime.now().isoformat()
    }

    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as file:
            try:
                history = json.load(file)
            except json.JSONDecodeError:
                history = []
    else:
        history = []

    history.append(log_entry)

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=2)

@app.route('/check_url', methods=['POST'])
def check_url():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = check_url_safety(url)

    # Add reputation score (dummy logic)
    result["reputation_score"] = 85 if result.get("is_safe") else 25

    # Get page title
    result["page_title"] = get_page_title(url)

    # Log the check
    log_check(result)

    status_code = 500 if "error" in result else 200
    return jsonify(result), status_code

@app.route('/analytics', methods=['GET'])
def get_analytics():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as file:
            try:
                history = json.load(file)
            except json.JSONDecodeError:
                history = []
        return jsonify(history), 200
    else:
        return jsonify([]), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
