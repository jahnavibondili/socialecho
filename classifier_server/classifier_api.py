from flask import Flask, request, jsonify
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Get HuggingFace API Key
HF_API_KEY = os.getenv("INTERFACE_API_KEY")
print("HF KEY:", HF_API_KEY)

# HuggingFace Router Endpoint
HF_API_URL = "https://router.huggingface.co/hf-inference/models/facebook/bart-large-mnli"

# Candidate labels
CANDIDATE_LABELS = [
    'programming',
    'health_and_fitness',
    'travel',
    'food_and_cooking',
    'music',
    'sports',
    'fashion',
    'art_and_design',
    'business_and_entrepreneurship',
    'education',
    'photography',
    'gaming',
    'science_and_technology',
    'parenting',
    'politics',
    'environment_and_sustainability',
    'beauty_and_skincare',
    'literature',
]

# Headers
headers = {
    "Authorization": f"Bearer {HF_API_KEY}",
    "Content-Type": "application/json"
}

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "response": {
            "status": 200,
            "statusText": "Classifier API Running"
        }
    })


@app.route('/classify', methods=['POST'])
def classify():
    try:
        # Safely get JSON
        data = request.get_json()

        if not data:
            raise ValueError("JSON body missing")

        if 'text' not in data or data['text'].strip() == "":
            raise ValueError("Text is required")

        text = data['text']

        # Prepare payload
        payload = {
            "inputs": text,
            "parameters": {
                "candidate_labels": CANDIDATE_LABELS
            }
        }

        # Send request to HuggingFace
        response = requests.post(HF_API_URL, headers=headers, json=payload)
        result = response.json()

        print("HF RESULT:", result)
        print("TYPE:", type(result))

        # HuggingFace router returns list of {label, score}
        if not isinstance(result, list):
            raise ValueError(f"Unexpected response format: {result}")

        categories = []

        for item in result:
            categories.append({
                "label": item["label"].capitalize().replace("_", " "),
                "score": item["score"]
            })

        # Sort by highest score
        categories_sorted = sorted(categories, key=lambda x: x["score"], reverse=True)

        return jsonify({
            "response": {
                "categories": categories_sorted
            }
        })
    except Exception as e:
        print("ERROR:", str(e))
        return jsonify({
            "response": {
                "status": 500,
                "statusText": str(e)
            }
        })


if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5000, debug=True)
