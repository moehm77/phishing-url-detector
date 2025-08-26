import streamlit as st
import pandas as pd
import joblib
from urllib.parse import urlparse
import re
import math
from collections import Counter

# Load trained model
model = joblib.load(r"C:\Users\pc\Desktop\final\phishing_url_model.pkl")

# Helper functions
def is_whitelisted(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Check for .edu or .gov anywhere in the TLD/second-level domain
        return (".edu." in domain or domain.endswith(".edu") or
                ".gov." in domain or domain.endswith(".gov"))
    except:
        return False

def has_brand_name(url, brands=["paypal", "google", "facebook", "github"]):
    return int(any(brand in url.lower() for brand in brands))

def weighted_suspicious_word(url):
    parsed = urlparse(url)
    domain_part = parsed.netloc.lower()
    path_part = parsed.path.lower()
    suspicious_words = ["secure", "account", "update", "verify", "bank"]
    
    # Weight 1 if word in domain, 0.5 if only in path, 0 otherwise
    for word in suspicious_words:
        if word in domain_part:
            return 1
        if word in path_part:
            return 0.5
    return 0

# Advanced feature extraction with weighted suspicious words
BRAND_NAMES = [
    "paypal", "bankofamerica", "github", "google", "facebook", 
    "linkedin", "instagram", "twitter", "amazon", "netflix", "coinbase", "binance"
]

# List of suspicious words often used in phishing URLs
SUSPICIOUS_WORDS = [
    "secure", "account", "update", "login", "verify", "signin", "webscr", "confirm", "alert"
]

def entropy(s):
    """Calculate Shannon entropy of a string."""
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob]) if prob else 0

def extract_features(url, weight_https=0.7):
    """
    Extracts features from a URL for phishing detection.
    weight_https: factor to down-weight is_https feature
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        
        # Main domain: last two parts of domain
        parts = domain.split('.')
        if len(parts) >= 2:
            main_domain = parts[-2] + '.' + parts[-1]
        else:
            main_domain = domain
        
        # Subdomain: everything before main domain
        subdomain = domain.replace('.' + main_domain, '')
        
        features = {}
        
        # Basic URL properties
        features["url_length"] = len(url)
        features["num_dots"] = url.count(".")
        features["num_hyphens"] = url.count("-")
        features["has_at_symbol"] = 1 if "@" in url else 0
        features["has_ip"] = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) else 0
        features["num_subdomains"] = subdomain.count(".")
        features["is_https"] = 1 if parsed.scheme == "https" else 0
        features["num_query_params"] = len(parsed.query.split("&")) if parsed.query else 0
        features["path_length"] = len(path)
        features["num_path_segments"] = len(path.split("/")) - 1 if path else 0
        features["entropy"] = entropy(url)
        
        # Suspicious word feature
        features["has_suspicious_word"] = int(any(word in url.lower() for word in SUSPICIOUS_WORDS))
        
        # Brand-safe / suspicious brand feature
        # 1 if a known brand is in subdomain but not in main domain → suspicious
        brand_flag = 0
        for brand in BRAND_NAMES:
            if brand in domain:
                if brand not in main_domain:
                    brand_flag = 1  # suspicious
        features["has_brand_name_suspicious"] = brand_flag
        
        # Down-weight HTTPS
        features["is_https"] *= weight_https
        
        return features
    except:
        return None
# Streamlit UI
st.title("Phishing URL Detector")
st.markdown("""
⚠️ **Disclaimer**:  
This tool is built for **educational and demo purposes only**.  
It is **not a production-grade phishing detector**.  
For real-world protection, always rely on official cybersecurity tools.
""", unsafe_allow_html=True)
url_input = st.text_input("Enter a URL:")

if url_input:
     if is_whitelisted(url_input):
        st.success(f"✅ This URL is whitelisted (.edu or .gov) and considered safe: {url_input}")
     else:
        features = extract_features(url_input)  # or brand-safe version
        if features is None:
            st.error("Invalid or malformed URL. Please try again.")
        else:
            X_test = pd.DataFrame([features])
            phishing_prob = model.predict_proba(X_test)[0][1]
            threshold = 0.5
            if phishing_prob >= threshold:
                st.error(f"🚨 Phishing URL detected! (Probability: {phishing_prob:.2f})")
            else:
                st.success(f"✅ Legitimate URL. (Phishing Probability: {phishing_prob:.2f})")
            st.markdown("### 🔍 Extracted Features")
            # Pretty-print features as a table
            features_df = pd.DataFrame(list(features.items()), columns=["Feature", "Value"])

            st.table(features_df)
