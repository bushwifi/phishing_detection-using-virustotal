import base64
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Your VirusTotal API key
VIRUS_TOTAL_API_KEY = "9f6604cca0d379302f138a1c6385319a7794e60947b73232b229e7842cb11f99"

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')

    # Call VirusTotal API
    headers = {
        "x-apikey": VIRUS_TOTAL_API_KEY
    }
    vt_url = "https://www.virustotal.com/api/v3/urls"

    # Base64 encode the URL to create the ID for retrieving analysis
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Analyze URL
    try:
        # Send the GET request to retrieve the analysis
        analysis_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        analysis_result = requests.get(analysis_url, headers=headers)

        # Log the result of the analysis request
        print("VirusTotal Analysis Result:", analysis_result.text)

        if analysis_result.status_code == 200:
            analysis_data = analysis_result.json()
            harmless = analysis_data["data"]["attributes"]["last_analysis_stats"]["harmless"]
            malicious = analysis_data["data"]["attributes"]["last_analysis_stats"]["malicious"]

            result = {
                "status": "phishing" if malicious > 0 else "safe",
                "details": f"Harmless: {harmless}, Malicious: {malicious}"
            }
            return jsonify(result)

        return jsonify({"status": "error", "details": "Unable to retrieve analysis results."})

    except Exception as e:
        return jsonify({"status": "error", "details": str(e)})

if __name__ == '__main__':
    app.run(debug=True)
