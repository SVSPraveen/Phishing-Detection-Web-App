# train_model.py
# This script trains a machine learning model using PhishTank and Tranco datasets.

# --- 1. Import Necessary Libraries ---
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
from urllib.parse import urlparse
import re
import time

print("Script started...")

# --- 2. Feature Extraction Functions ---
# These must be the EXACT same functions as in app.py
def get_url_length(url):
    return len(str(url))

def get_hostname_length(url):
    return len(urlparse(str(url)).netloc)

def has_ip_address(url):
    try:
        ip_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
        )
        match = ip_pattern.search(urlparse(str(url)).netloc)
        return 1 if match else 0
    except:
        return 0

def count_special_character(url, char):
    return str(url).count(char)

# --- 3. Load and Prepare the Datasets ---
print("Loading PhishTank and Tranco datasets...")
try:
    # Load the phishing URLs from PhishTank
    phishing_df = pd.read_csv('verified_online.csv')
    phishing_df = phishing_df[['url']]
    phishing_df = phishing_df.rename(columns={'url': 'URL'})
    phishing_df['Target'] = 'yes'
    print(f"Loaded {len(phishing_df)} phishing URLs from PhishTank.")

    # Load the legitimate URLs from Tranco (assuming it's named 'top-1m.csv')
    legitimate_df = pd.read_csv('top-1m.csv', names=['rank', 'URL'])
    legitimate_df['URL'] = 'http://' + legitimate_df['URL']
    legitimate_df['Target'] = 'no'
    print(f"Loaded {len(legitimate_df)} legitimate URLs from Tranco.")

    # --- Balance the dataset ---
    # Take a sample of legitimate URLs that matches the number of phishing URLs
    num_phishing = len(phishing_df)
    legitimate_df = legitimate_df.sample(n=num_phishing, random_state=42)
    print(f"Balanced dataset with {len(legitimate_df)} legitimate URLs.")

    # --- Combine the datasets ---
    df = pd.concat([phishing_df, legitimate_df], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True) # Shuffle the data

    print(f"Created final dataset with {len(df)} total URLs.")

except FileNotFoundError as e:
    print(f"Error: A dataset file was not found. Make sure 'verified_online.csv' and 'top-1m.csv' are in the directory.")
    print(e)
    exit()


# --- 4. Feature Engineering ---
print("Extracting features from URLs... This might take a moment.")
start_time = time.time()

# (This section remains unchanged)
df['url_length'] = df['URL'].apply(get_url_length)
df['hostname_length'] = df['URL'].apply(get_hostname_length)
df['ip_address'] = df['URL'].apply(has_ip_address)
df['num_dots'] = df['URL'].apply(lambda x: count_special_character(x, '.'))
df['num_hyphens'] = df['URL'].apply(lambda x: count_special_character(x, '-'))
df['num_at'] = df['URL'].apply(lambda x: count_special_character(x, '@'))
df['num_question'] = df['URL'].apply(lambda x: count_special_character(x, '?'))
df['num_and'] = df['URL'].apply(lambda x: count_special_character(x, '&'))
df['num_or'] = df['URL'].apply(lambda x: count_special_character(x, '|'))
df['num_equals'] = df['URL'].apply(lambda x: count_special_character(x, '='))
df['num_underscore'] = df['URL'].apply(lambda x: count_special_character(x, '_'))
df['num_tilde'] = df['URL'].apply(lambda x: count_special_character(x, '~'))
df['num_percent'] = df['URL'].apply(lambda x: count_special_character(x, '%'))
df['num_slash'] = df['URL'].apply(lambda x: count_special_character(x, '/'))
df['num_star'] = df['URL'].apply(lambda x: count_special_character(x, '*'))
df['num_colon'] = df['URL'].apply(lambda x: count_special_character(x, ':'))
df['num_comma'] = df['URL'].apply(lambda x: count_special_character(x, ','))
df['num_semicolon'] = df['URL'].apply(lambda x: count_special_character(x, ';'))
df['num_dollar'] = df['URL'].apply(lambda x: count_special_character(x, '$'))
df['num_space'] = df['URL'].apply(lambda x: count_special_character(x, ' '))
df['num_www'] = df['URL'].apply(lambda x: 1 if 'www.' in urlparse(str(x)).netloc else 0)

end_time = time.time()
print(f"Feature extraction completed in {end_time - start_time:.2f} seconds.")

# --- 5. Prepare Data for Training ---
# (This section remains unchanged)
feature_columns = [
    'url_length', 'hostname_length', 'ip_address', 'num_dots', 'num_hyphens',
    'num_at', 'num_question', 'num_and', 'num_or', 'num_equals', 'num_underscore',
    'num_tilde', 'num_percent', 'num_slash', 'num_star', 'num_colon',
    'num_comma', 'num_semicolon', 'num_dollar', 'num_space', 'num_www'
]
X = df[feature_columns]
y = df['Target'].apply(lambda x: 1 if x == 'yes' else 0)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Data split into {len(X_train)} training samples and {len(X_test)} testing samples.")

# --- 6. Train the Model ---
# (This section remains unchanged)
print("Training the Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)
print("Model training completed.")

# --- 7. Evaluate the Model ---
# (This section remains unchanged)
print("Evaluating model performance...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print("\n--- Model Evaluation Results ---")
print(f"Accuracy: {accuracy:.4f} ({accuracy:.2%})")
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
print("---------------------------------\n")

# --- 8. Save the Trained Model ---
# (This section remains unchanged)
print("Saving the trained model to 'model.pkl'...")
joblib.dump(model, 'model.pkl')
print("Model saved successfully! Your web app is now ready with a real model.")
