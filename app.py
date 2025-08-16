# app.py - The backend server for our phishing detector.
# We'll use the Flask framework to create a simple web server.

# --- 1. Import Necessary Libraries ---
from flask import Flask, request, jsonify, render_template
import joblib  # To load our pre-trained machine learning model
import pandas as pd # To handle data in a structured way (DataFrame)
from urllib.parse import urlparse # To break down URLs into their components
import re # To use regular expressions for pattern matching (like finding IP addresses)

# --- 2. Initialize the Flask App ---
# This creates an instance of the Flask web application.
app = Flask(__name__, template_folder='templates', static_folder='static')

# --- 3. Feature Extraction Functions ---
# These functions take a URL and extract specific numerical features from it.
# Our machine learning model was trained on these exact features.

def get_url_length(url):
    """Returns the total number of characters in the URL."""
    return len(url)

def get_hostname_length(url):
    """Returns the number of characters in the hostname (e.g., 'www.google.com')."""
    return len(urlparse(url).netloc)

def has_ip_address(url):
    """Checks if the hostname of the URL is an IP address. Returns 1 if true, 0 if false."""
    try:
        # A regular expression to match IPv4 and IPv6 patterns
        ip_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])' # IPv4
            r'|'
            r'([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}' # IPv6
        )
        match = ip_pattern.search(urlparse(url).netloc)
        return 1 if match else 0
    except:
        return 0 # Return 0 in case of any parsing errors

def count_special_character(url, char):
    """Counts the occurrences of a specific special character in the URL."""
    return url.count(char)

# --- 4. Load the Machine Learning Model ---
# We load the model we trained earlier. It's stored in a file called 'model.pkl'.
# We use a try-except block to handle the case where the file might be missing.
try:
    model = joblib.load('model.pkl')
    print("Model loaded successfully.")
except FileNotFoundError:
    print("Error: 'model.pkl' not found. The app will not be able to make predictions.")
    model = None # If the model can't be loaded, we set it to None.

# --- 5. Define the Routes (API Endpoints) ---

@app.route('/')
def home():
    """This route serves our main HTML page."""
    # Flask will look for 'index.html' in the 'templates' folder.
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    """This route handles the prediction logic."""
    # First, check if the model was loaded correctly.
    if model is None:
        return jsonify({'error': 'Model is not available. Please check server logs.'}), 500

    try:
        # Get the JSON data sent from our frontend JavaScript.
        data = request.get_json()
        url = data['url']
        
        # Make sure the URL has a scheme (http or https) for proper parsing.
        if not url.startswith(('http://', 'https://')):
             url = 'http://' + url

        # --- Extract features from the submitted URL ---
        # The feature names must exactly match the ones used during model training.
        features = {
            'url_length': get_url_length(url),
            'hostname_length': get_hostname_length(url),
            'ip_address': has_ip_address(url),
            'num_dots': count_special_character(url, '.'),
            'num_hyphens': count_special_character(url, '-'),
            'num_at': count_special_character(url, '@'),
            'num_question': count_special_character(url, '?'),
            'num_and': count_special_character(url, '&'),
            'num_or': count_special_character(url, '|'),
            'num_equals': count_special_character(url, '='),
            'num_underscore': count_special_character(url, '_'),
            'num_tilde': count_special_character(url, '~'),
            'num_percent': count_special_character(url, '%'),
            'num_slash': count_special_character(url, '/'),
            'num_star': count_special_character(url, '*'),
            'num_colon': count_special_character(url, ':'),
            'num_comma': count_special_character(url, ','),
            'num_semicolon': count_special_character(url, ';'),
            'num_dollar': count_special_character(url, '$'),
            'num_space': count_special_character(url, ' '),
            'num_www': 1 if 'www.' in urlparse(url).netloc else 0,
        }

        # Convert the dictionary of features into a pandas DataFrame.
        # The model expects a DataFrame as input.
        df = pd.DataFrame([features])
        
        # --- Make a Prediction ---
        # 'predict_proba' gives the probability for each class (0 for legitimate, 1 for phishing).
        prediction_proba = model.predict_proba(df)[0]
        phishing_probability = prediction_proba[1] # We want the probability of it being phishing.

        # Classify based on a 50% probability threshold.
        result_label = 'Phishing' if phishing_probability > 0.5 else 'Legitimate'
        
        # --- Prepare the Response ---
        # We send back a JSON object with the prediction and confidence score.
        response = {
            'prediction': result_label,
            'confidence': f"{phishing_probability:.2%}" # Format the probability as a percentage string.
        }
        
        return jsonify(response)

    except Exception as e:
        # If any error occurs during the process, log it and send a generic error message.
        print(f"An error occurred during prediction: {e}")
        return jsonify({'error': 'An error occurred on the server. Please try again.'}), 500

# --- 6. Run the App ---
# This part of the script only runs when you execute 'python app.py' directly.
if __name__ == '__main__':
    # 'debug=True' is helpful for development as it automatically reloads the server on code changes.
    # For a real deployment, you would use a proper web server like Gunicorn.
    app.run(host='0.0.0.0', port=5000, debug=True)
