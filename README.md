# phishing-url-detector
Machine Learning model + Streamlit app to detect phishing URLs (educational demo)
#  Phishing URL Detector (Educational Demo)

Phishing websites are one of the most common ways attackers steal credentials.  
This project uses **Machine Learning + URL feature engineering** to predict whether a URL is **legitimate or phishing**.  

The project includes:
-  A trained ML model (scikit-learn)
-  An interactive **Streamlit web app**
-  A Jupyter notebook for training and feature extraction

⚠ **Disclaimer**:  
This tool is built for **educational/demo purposes only**.  
It is **not a production-grade phishing detector**. For real-world protection, always rely on official cybersecurity tools.

---

##  Features
- Extracts features from URLs:
  - Length, entropy, subdomain depth
  - Suspicious keywords (`login`, `secure`, `verify`, …)
  - Brand misuse (e.g., `paypal.secure-login.com`)
- Predicts phishing probability using a trained ML model
- Streamlit app for easy testing
- Displays extracted features in a table for transparency

---

## 🎥 Demo
🖥️ **Live App**: [Try it here](https://yourusername-phishing-url-detector.streamlit.app)  
