# PhishGuard
A phishing URL detection system using XGBoost ml model. It consists of a browser extension, a Python backend API, and a web dashboard and protects user from malicious URLs by blocking them.

## How it works?
When a user visits a URL, the browser extension sends it to the backend API, which extracts lexical features from the URL and runs them through a trained XGBoost classifier. Additioionaly, the backend performs active CTI, typo-squatting detection, and forensic analysis if required. The result (malicious or safe) is returned to the extension and displayed to the user. The dashboard provides a visual interface for monitoring and downloading logs.

```
## Project Structure
phishguard/
├── backend/        # Python API server (serves ML model predictions)
├── dashboard/      # Web frontend for URL scanning and results
├── extensions/     # Browser extension source code
├── notebooks/      # Jupyter notebooks for model training & analysis
└── ml_model_xgb.joblib  # Trained XGBoost model
```

## How to use?
Install the chrome extension to chrome. The system begins scanning immediately. The backend is deployed on a Render server so no need to run it separately. Refer to dashboard for analysis of scanned URLs.

**Dashboard:** https://friendly-mandazi-cc5db3.netlify.app/

## Tech Stack
```
ML Model: XGBoost 
Backend: Python
Dashboard: JavaScript, HTML, CSS
Extension: JavaScript
```
