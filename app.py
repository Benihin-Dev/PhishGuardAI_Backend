# Import required libraries
import pickle
import numpy as np
from urllib.parse import urlparse
import re
import tldextract
import whois
from datetime import datetime, timedelta
import requests
from bs4 import BeautifulSoup
import socket
import time
import warnings
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# Suppress warnings
warnings.filterwarnings("ignore")

# Path to the model
MODEL_PATH = "voting_model.pkl"

# Load the model
try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

# Constants
SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']

def get_domain_age(domain):
    """
    Gets the age of the domain in days.
    Returns the age and the creation date.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # Handle list of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Calculate age
        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            return age_days, creation_date.strftime("%Y-%m-%d")
        else:
            return "Unknown", "Unknown"
    except Exception as e:
        return "Unknown", "Unknown"

def get_network_info(url):
    """
    Get network information about the URL.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc

    # Remove www. if present
    if hostname.startswith('www.'):
        hostname = hostname[4:]

    network_info = {
        "IP Address": "Unknown",
        "Location": "Unknown",
        "Hostname": hostname,
        "Response Time": "Unknown",
        "Subdomain Count": 0,
        "Redirection Count": 0,
        "Redirection Chain": [url]
    }

    # Get IP address
    try:
        start_time = time.time()
        ip_address = socket.gethostbyname(hostname)
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        network_info["IP Address"] = ip_address
        network_info["Response Time"] = f"{response_time:.2f} ms"
    except Exception:
        pass

    # Get subdomain count
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    network_info["Subdomain Count"] = subdomain.count('.') + 1 if subdomain else 0

    # Check for redirections
    try:
        session = requests.Session()
        response = session.get(url, allow_redirects=True, timeout=10, verify=False)

        if response.history:
            network_info["Redirection Count"] = len(response.history)
            network_info["Redirection Chain"] = [r.url for r in response.history] + [response.url]
    except Exception:
        pass

    return network_info

def get_ssl_info(url):
    """
    Get SSL certificate information including status, expiry date, and issuer.
    """
    ssl_info = {
        "Status": "Invalid/Not Available",
        "Expiry Date": "N/A",
        "Issuer": "N/A"
    }

    # Only proceed if the URL uses HTTPS
    if not url.startswith("https://"):
        return ssl_info

    try:
        # Parse the hostname from the URL
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Remove port number if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        # Create an SSL context
        import ssl
        import socket
        from datetime import datetime

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)

        # Set a timeout to prevent hanging
        conn.settimeout(5.0)

        # Connect to the server
        conn.connect((hostname, 443))

        # Get the certificate
        cert = conn.getpeercert()

        if cert:
            # Extract certificate information
            ssl_info["Status"] = "Valid"

            # Get expiry date
            if 'notAfter' in cert:
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                ssl_info["Expiry Date"] = expiry_date.strftime("%Y-%m-%d")

            # Get issuer information
            if 'issuer' in cert:
                issuer_components = dict(x[0] for x in cert['issuer'])
                if 'organizationName' in issuer_components:
                    ssl_info["Issuer"] = issuer_components['organizationName']
                elif 'commonName' in issuer_components:
                    ssl_info["Issuer"] = issuer_components['commonName']

        # Close the connection
        conn.close()

    except Exception as e:
        # If there's an error, we keep the default values
        # But we can log the error for debugging
        print(f"Error getting SSL info: {e}")

    return ssl_info

def extract_features_from_url(url):
    """
    Extract features from a given URL for phishing detection.
    Returns a dictionary of features.
    """
    features = {
        "having_IP_Address": 0,
        "URL_Length": 0,
        "Shortining_Service": 0,
        "having_At_Symbol": 0,
        "double_slash_redirecting": 0,
        "Prefix_Suffix": 0,
        "SSLfinal_State": 0,
        "having_Sub_Domain": 0,
        "Domain_registeration_length": 0,
        "Request_URL": 0,
        "URL_of_Anchor": 0,
        "Links_in_tags": 0,
        "SFH": 0,
    }

    # Check if the URL is valid
    parsed = urlparse(url)
    if not all([parsed.scheme, parsed.netloc]):
        print(f"Invalid URL: {url}")
        return features  # Return default feature values

    # Store actual URL length
    features["URL_Length"] = len(url)

    # Check for IP Address
    features["having_IP_Address"] = 1 if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/|$)', url) else 0

    # Check URL Length for binary classification
    url_length_feature = 1 if len(url) > 75 else 0

    # Check for Shortening Service
    features["Shortining_Service"] = 1 if any(shortener in url for shortener in SHORTENERS) else 0

    # Check for "@" Symbol
    features["having_At_Symbol"] = 1 if '@' in url and not re.search(r'\w+@\w+\.\w+', url) else 0

    # Check for Double Slash Redirecting
    features["double_slash_redirecting"] = 1 if url.count('//') > 1 else 0

    # Check for Prefix-Suffix
    features["Prefix_Suffix"] = 1 if bool(re.search(r'(-|_)', urlparse(url).netloc)) else 0

    # Check SSL Final State
    features["SSLfinal_State"] = 0 if urlparse(url).scheme == 'https' else 1

    # Get subdomain count
    subdomain_count = get_subdomain_count(url)
    features["having_Sub_Domain"] = subdomain_count

    # Domain Registration Length
    domain = urlparse(url).netloc
    if domain.startswith('www.'):
        domain = domain[4:]

    try:
        w = whois.whois(domain)
        expiry = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        if isinstance(expiry, datetime) and isinstance(creation, datetime):
            registration_length = (expiry - creation).days
            features["Domain_registeration_length"] = registration_length
            # For binary feature
            domain_reg_feature = 0 if registration_length > 365 else 1
        else:
            features["Domain_registeration_length"] = 0
            domain_reg_feature = 1  # Default for invalid dates
    except Exception as e:
        features["Domain_registeration_length"] = 0
        domain_reg_feature = 1  # Default on error

    # Request URL and other features with retry logic
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept-Language': 'en-US,en;q=0.5'
    }

    retries = 3
    for attempt in range(retries):
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=(3.05, 10),  # Connect timeout 3.05s, read timeout 10s
                allow_redirects=True,
                verify=False  # Warning: Disables SSL verification
            )
            response.raise_for_status()  # Raise an error for bad responses
            soup = BeautifulSoup(response.content, 'html.parser')
            break  # Break if successful
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt == retries - 1:
                print(f"Error fetching URL {url}: {e}")
                return features  # Return features even if request fails

    # Request URL feature
    tags_to_check = ['img', 'script', 'link', 'iframe', 'embed', 'source']
    resources = soup.find_all(tags_to_check)

    # Count external resources
    external_resources = sum(
        1 for res in resources
        if (res.get('src') or res.get('href')) and
        urlparse(res.get('src') or res.get('href')).netloc and
        urlparse(res.get('src') or res.get('href')).netloc != urlparse(url).netloc
    )

    # Total resources
    total_resources = len(resources)

    # Update feature based on external resources ratio
    features["Request_URL"] = external_resources / (total_resources + 1e-6)

    # URL of Anchor feature
    valid_anchors = 0
    suspicious_anchors = 0
    suspicious_prefixes = ('#', 'javascript:', 'data:', 'about:', 'tel:', 'mailto:')

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']

        # Check for suspicious prefixes
        if any(href.startswith(prefix) for prefix in suspicious_prefixes):
            suspicious_anchors += 1
        elif (urlparse(href).netloc and
              urlparse(href).netloc != urlparse(url).netloc and
              not href.startswith('/')):
            suspicious_anchors += 1

        valid_anchors += 1

    # Update feature based on the ratio of suspicious anchors
    features["URL_of_Anchor"] = suspicious_anchors / (valid_anchors + 1e-6)

    # Links in Tags feature
    external_links_in_tags = sum(1 for tag in soup.find_all(['script', 'link', 'img'])
                                   if tag.get('src') and urlparse(tag.get('src')).netloc != urlparse(url).netloc)
    total_links_in_tags = len(soup.find_all(['script', 'link', 'img']))
    features["Links_in_tags"] = external_links_in_tags / (total_links_in_tags + 1e-6)

    # SFH feature
    sfh = None
    form_tag = soup.find('form')

    if form_tag and form_tag.has_attr('action'):
        sfh = form_tag['action']

    if sfh:
        parsed_sfh = urlparse(sfh)
        if not parsed_sfh.netloc:  # Relative path
            features["SFH"] = 0
        elif parsed_sfh.netloc == urlparse(url).netloc:
            features["SFH"] = 0  # Internal is good
        else:
            features["SFH"] = 1  # External is bad
    else:
        features["SFH"] = 1  # Missing action is suspicious

    # Create feature set for model prediction (binary features)
    model_features = {
        "having_IP_Address": features["having_IP_Address"],
        "URL_Length": url_length_feature,
        "Shortining_Service": features["Shortining_Service"],
        "having_At_Symbol": features["having_At_Symbol"],
        "double_slash_redirecting": features["double_slash_redirecting"],
        "Prefix_Suffix": features["Prefix_Suffix"],
        "SSLfinal_State": features["SSLfinal_State"],
        "having_Sub_Domain": features["having_Sub_Domain"],
        "Domain_registration_length": domain_reg_feature,
        "Request_URL": 1 if features["Request_URL"] > 0.5 else 0,
        "URL_of_Anchor": 1 if features["URL_of_Anchor"] > 0.5 else 0,
        "Links_in_tags": 1 if features["Links_in_tags"] > 0.5 else 0,
        "SFH": features["SFH"]
    }

    return features, model_features

def get_subdomain_count(url):
    """
    Extracts and counts the number of subdomains in a URL and assesses phishing possibility.
    Returns 1 for likely phishing and why0 for legitimate URLs.
    """
    try:
        # Parse the URL to extract hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        # Check if the hostname is an IP address
        if not hostname or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            return 1  # Likely phishing if it's an IP address

        # Use tldextract for robust domain component extraction
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        tld = extracted.suffix

        # List of common TLDs (this can be expanded)
        common_tlds = ["com", "org", "net", "edu", "gov", "uk", "lk", "co", "info"]

        # Validate the TLD
        if tld not in common_tlds:
            return 1  # Likely phishing if TLD is uncommon

        # Count subdomains using tldextract result
        subdomain_count = subdomain.count('.') + 1 if subdomain else 0

        # Assess phishing possibility based on subdomain count
        if subdomain_count > 1:
            return 1  # Likely phishing
        else:
            return 0  # Legitimate URL

    except Exception as e:
        print(f"Error parsing URL for subdomain count: {e}")
        return 1  # Default to phishing in case of an error

def determine_risk_level(phishing_prob):
    """
    Determine risk level based on phishing probability.
    """
    if phishing_prob < 0.25:
        return "Low Risk"
    elif phishing_prob < 0.50:
        return "Medium Risk"
    elif phishing_prob < 0.75:
        return "High Risk"
    else:
        return "Very High Risk"

def predict_url(url):
    """
    Predict if a URL is phishing or legitimate and format in the requested output.
    """
    if model is None:
        return {"Error": "Model not loaded"}

    try:
        # Extract features
        raw_features, model_features = extract_features_from_url(url)

        # Get domain for age calculation
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain.startswith('www.'):
            domain = domain[4:]

        domain_age, creation_date = get_domain_age(domain)
        network_info = get_network_info(url)
        ssl_info = get_ssl_info(url)

        # Convert to array in correct order for model prediction
        feature_order = [
            "having_IP_Address", "URL_Length", "Shortining_Service",
            "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
            "SSLfinal_State", "having_Sub_Domain", "Domain_registration_length",
            "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH"
        ]
        feature_values = np.array([model_features[key] for key in feature_order]).reshape(1, -1)

        # Make prediction
        prediction = model.predict(feature_values)[0]
        proba = model.predict_proba(feature_values)[0]

        # Interpret probabilities - Using the fixed interpretation
        phishing_prob = proba[0]  # Phishing probability
        legit_prob = proba[1]     # Legitimate probability

        # Determine prediction text and risk level
        prediction_text = "Legitimate" if legit_prob > 0.5 else "Phishing"
        risk_level = determine_risk_level(phishing_prob)

        # Format results according to the requested format
        result = {
            "URL": url,
            "Prediction": prediction_text,
            "Raw_Prediction_Value": int(prediction),
            "Risk_Level": risk_level,
            "Domain_Age": f"{domain_age} days" if isinstance(domain_age, int) else domain_age,
            "Network_Information": network_info,
            "SSL_Certificate": ssl_info,
            "Features": raw_features,
            "Probability_Legitimate": f"{legit_prob*100:.2f}%",
            "Probability_Phishing": f"{phishing_prob*100:.2f}%"
        }

        return result

    except Exception as e:
        return {"Error": f"Error analyzing URL: {str(e)}"}

# Create FastAPI app
app = FastAPI(
    title="Phishing Detection API",
    description="API for detecting phishing URLs using machine learning",
    version="1.0.0"
)

# Define request model
class URLRequest(BaseModel):
    url: str

@app.get("/")
async def root():
    return {"message": "*ththa Nampikka ellayaada Unkalukku!.."}

# In the predict endpoint function:
@app.post("/predict")
async def predict(request: URLRequest):
    """
    Analyze a URL and predict if it's phishing or legitimate
    """
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    # Validate URL format before processing
    try:
        parsed = urlparse(request.url)
        if not all([parsed.scheme, parsed.netloc]):
            raise HTTPException(status_code=400, detail="Invalid URL format")
        
        # Additional validation to ensure the URL is properly formed
        if parsed.scheme not in ['http', 'https']:
            raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {str(e)}")
    
    result = predict_url(request.url)
    
    if "Error" in result:
        raise HTTPException(status_code=500, detail=result["Error"])
    
    return result

# Run the application

# Leave the app variable exposed for Vercel