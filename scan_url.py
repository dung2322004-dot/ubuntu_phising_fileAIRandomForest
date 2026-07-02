import pandas as pd
import joblib

from url_features import *

# ===============================
# Load AI Model
# ===============================

model = joblib.load("rf_9criteria.pkl")

url = input("Enter URL: ")

# ===============================
# Feature Extraction
# (Input cho Random Forest)
# ===============================

reputation = domain_reputation(url)
age = get_domain_age(url)
ssl = has_ssl(url)

structure = url_structure(url)

typo = typo_score(url)
redirect = redirect_count(url)
blacklist = blacklist_score(url)
content = content_score(url)
headers = security_headers(url)

print("\n========== FEATURE EXTRACTION ==========")

print("Domain Reputation :", reputation)
print("Domain Age        :", age)
print("SSL/TLS           :", ssl)
print("URL Length        :", structure["url_length"])
print("Typosquatting     :", typo)
print("Redirect Count    :", redirect)
print("Blacklist Score   :", blacklist)
print("Content Score     :", content)
print("Security Headers  :", headers)

# ===============================
# Feature Vector
# ===============================

features = pd.DataFrame([{
    "domain_reputation": reputation,
    "domain_age": age,
    "ssl": ssl,
    "url_length": structure["url_length"],
    "typo": typo,
    "redirect": redirect,
    "blacklist": blacklist,
    "content": content,
    "headers": headers
}])


# ===============================
# Rule-based Risk Assessment
# ===============================

risk = 0

# Domain Reputation
if reputation < 20:
    risk += 20
elif reputation < 50:
    risk += 10

# Domain Age
if age == -1:
    risk += 15
elif age < 180:
    risk += 25
elif age < 365:
    risk += 10

# SSL
if ssl == 0:
    risk += 20

# URL Length
if structure["url_length"] > 100:
    risk += 15
elif structure["url_length"] > 75:
    risk += 10

# Typosquatting
if typo == 1:
    risk += 25

# Redirect
if redirect > 3:
    risk += 10

# Blacklist
if blacklist >= 3:
    risk += 20
elif blacklist >= 1:
    risk += 10

# Content
if content > 5:
    risk += 20
elif content > 3:
    risk += 10

# Security Headers
if headers == 0:
    risk += 10

risk = min(risk, 100)

if risk < 30:
    level = "SAFE"
elif risk < 60:
    level = "SUSPICIOUS"
else:
    level = "PHISHING"

print("\n========== RULE-BASED RISK ASSESSMENT ==========")

print("Risk Score :", risk, "%")
print("Risk Level :", level)

# ===============================
# AI Prediction
# ===============================

prediction = model.predict(features)[0]

probability = max(
    model.predict_proba(features)[0]
) * 100

print("\n")
if prediction == 1:
    print("=> AI Prediction        : PHISHING")
else:
    print("=> AI Prediction        : SAFE")

print(
    "=> Model Confidence     :",
    round(probability,2),
    "%"
)
