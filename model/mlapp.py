from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# Load trained ML model and preprocessors
model = joblib.load("sus.pkl") 
imputer = joblib.load('imputer.pkl')
label_encoders = joblib.load('label_encoders.pkl')

@app.route("/")
def home():
    return "ML Model API is running!"

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get JSON data from request (expects an array of job details)
        data = request.json  

        if not isinstance(data, list):  # Ensure input is a list
            return jsonify({"error": "Input should be a list of job details"}), 400
        
        # Convert input JSON to Pandas DataFrame
        features = pd.DataFrame(data)  

        # Drop "OFFSET (V)" if it exists
        if "OFFSET (V)" in features.columns:
            features.drop(columns=["OFFSET (V)"], inplace=True)

        # Ensure all expected columns exist
        required_features = set(label_encoders.keys())
        missing_features = required_features - set(features.columns)
        if missing_features:
            return jsonify({"error": f"Missing required features: {missing_features}"}), 400

        # Apply label encoding with error handling
        for column in features.select_dtypes(include=['object']).columns:
            if column in label_encoders:
                le = label_encoders[column]
                features[column] = features[column].astype(str)  # Convert to string
                
                # Handle unseen labels
                features[column] = features[column].apply(lambda x: x if x in le.classes_ else "unknown")
                
                # Update encoder classes if "unknown" is not in training data
                if "unknown" not in le.classes_:
                    le.classes_ = np.append(le.classes_, "unknown")
                
                # Transform values
                features[column] = le.transform(features[column])

        # Handle missing values using the imputer
        features = pd.DataFrame(imputer.transform(features), columns=features.columns)

        # Make predictions
        predictions = model.predict(features)

        # Return predictions as JSON
        return jsonify({"predictions": predictions.tolist()})  

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
