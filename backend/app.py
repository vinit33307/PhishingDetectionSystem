from flask import Flask, request, jsonify, render_template, redirect
from dotenv import load_dotenv
import os
from pymongo import MongoClient
from utils.heuristic import check_heuristics
from utils.blacklist import check_google_safe_browsing  # Import your blacklist checker

load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

app = Flask(__name__)

# Connect to MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client.phishing_db
collection = db.phishing_attempts

@app.route('/dashboard')
def dashboard():
    logs = list(collection.find().sort('_id', -1).limit(50))  # latest 50 logs
    for log in logs:
        log['_id'] = str(log['_id'])
    return render_template('dashboard.html', logs=logs)

@app.route('/check_url_form', methods=['POST'])
def check_url_form():
    url = request.form.get('url')
    if not url:
        return redirect('/dashboard')

    is_phishing, heuristics = check_heuristics(url)
    is_blacklisted_google = False
    is_blacklisted_phishtank = False

    try:
        is_blacklisted_google = check_google_safe_browsing(url)
    except Exception as e:
        print(f"Google error: {e}")

    try:
        is_blacklisted_phishtank = False
        # is_blacklisted_phishtank = check_phishtank(url)
    except Exception as e:
        print(f"PhishTank error: {e}")

    phishing_final = is_phishing or is_blacklisted_google or is_blacklisted_phishtank

    result = {
        'url': url,
        'is_phishing': phishing_final,
        'detected_by': {
            'heuristics': is_phishing,
            'google_blacklist': is_blacklisted_google,
            'phishtank_blacklist': is_blacklisted_phishtank
        },
        'details': heuristics
    }

    # Store the result in MongoDB
    insert_result = collection.insert_one(result)
    result['_id'] = str(insert_result.inserted_id)

    # Reload logs including the new one
    logs = list(collection.find().sort('_id', -1).limit(50))
    for log in logs:
        log['_id'] = str(log['_id'])

    return render_template('dashboard.html', logs=logs, result=result)

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    collection.delete_many({})
    return redirect('/dashboard')

@app.route('/')
def home():
    return "Phishing Detection System API Running"

@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL not provided'}), 400

    # Run heuristic detection
    is_phishing, heuristics = check_heuristics(url)

    # Run Google Safe Browsing blacklist check
    is_blacklisted = False
    try:
        is_blacklisted = check_google_safe_browsing(url)
    except Exception as e:
        print(f"Google Safe Browsing API error: {e}")

    phishing_final = is_phishing or is_blacklisted

    result = {
        'url': url,
        'is_phishing': phishing_final,
        'detected_by': {
            'heuristics': is_phishing,
            'blacklist': is_blacklisted
        },
        'details': heuristics
    }

    insert_result = collection.insert_one(result)
    result['_id'] = str(insert_result.inserted_id)

    return jsonify(result), 200

if __name__ == '__main__':
    app.run(debug=True)
