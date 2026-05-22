import os
import re
import requests
import tldextract
from datetime import datetime
from dotenv import load_dotenv
from database import get_cached_domain_age, set_cached_domain_age

load_dotenv()

API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"


def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)


def check_urls_with_google(urls):
    if not urls:
        return False

    payload = {
        "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in urls]
        }
    }

    try:
        response = requests.post(GOOGLE_API_URL, json=payload)
        response.raise_for_status()
        data = response.json()
        print(f"[*] Google Response: {data}")
        if "matches" in data:
            print(f"[!] Google Safe Browsing Alert: Found {len(data['matches'])} threats!")
            return True
        return False
    except Exception as e:
        print(f"[-] Error connecting to Google API: {e}")
        return False


def get_domain_age_info(domain_name):
    if "@" in domain_name:
        domain_name = domain_name.split('@')[-1]
    domain_name = domain_name.lower().strip()

    # --- מנגנון מניעת Rate Limit (זיכרון מטמון) ---
    cached_age = get_cached_domain_age(domain_name)
    if cached_age is not None:
        print(f"[*] Cache Hit: Loaded {domain_name} from database. Skipping external API.")
        age_days = cached_age
    else:
        rdap_url = f"https://rdap.org/domain/{domain_name}"
        try:
            print(f"[*] Fetching RDAP data for: {domain_name}")
            response = requests.get(rdap_url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                events = data.get('events', [])

                found_date = False

                for event in events:
                    action = event.get('eventAction', event.get('action', '')).lower()

                    if action in ['registration', 'create']:
                        reg_date_str = event.get('eventDate')
                        if reg_date_str:
                            reg_date = datetime.strptime(reg_date_str[:10], '%Y-%m-%d')
                            age_days = (datetime.now() - reg_date).days

                            set_cached_domain_age(domain_name, age_days)
                            found_date = True
                            break

                if not found_date:
                    print(f"[-] RDAP warning: No registration date found in events for {domain_name}.")
                    return 20, "Domain exists but age not confirmed (Privacy enabled)"

            else:
                print(f"[-] RDAP server returned {response.status_code} for {domain_name}")
                return 30, "Could not verify domain age (Unsupported TLD or Private)"

        except Exception as e:
            print(f"[-] RDAP Network Error for {domain_name}: {e}")
            return 30, "Could not verify domain age (Network Error)"

    # חישוב הניקוד לפי גיל הדומיין
    if age_days <= 4:
        return 90, f"Critical: Domain is only {age_days} days old"
    elif age_days <= 30:
        return 50, f"Suspicious: Domain is {age_days} days old"

    return 0, f"Domain age: {age_days} days"


# הוספנו את ה-headers כפרמטר לפונקציה
def analyze_email_content(sender, subject, body, headers=""):
    score = 0
    reasons = []
    subject_lower = subject.lower()
    body_lower = body.lower()

    # --- בדיקה מול גוגל ---
    found_urls = extract_urls(body_lower)
    if found_urls:
        print(f"[*] Found URLs to analyze: {found_urls}")
        is_malicious = check_urls_with_google(found_urls)
        if is_malicious:
            print("[!!!] URL flagged as DANGEROUS by Google!")
            score += 100
            reasons.append("Contains a known malicious link (Google Safe Browsing)")

    try:
        raw_domain = sender.split("@")[-1].strip(">").strip()
        ext = tldextract.extract(raw_domain)
        domain = f"{ext.domain}.{ext.suffix}"
        if "demo" in subject_lower or "דמו" in subject_lower:
            age_risk = 90
            age_desc = "Critical: Domain is only 0 days old (Simulated)"
        else:
            age_risk, age_desc = get_domain_age_info(domain)

        if age_risk > 0:
            print(f"[*] Domain Age Check: {age_desc} (+{age_risk} points)")
            score += age_risk
            reasons.append(age_desc)

    except Exception as e:
        print(f"[-] Domain analysis failed: {e}")
        pass

    shady_extensions = [".xyz", ".top", ".ru", ".cn", ".biz", ".info"]
    if any(ext in sender.lower() for ext in shady_extensions):
        score += 30
        reasons.append("Sender uses a highly suspicious domain extension")

    urgent_subject_words = ["urgent", "password", "suspended", "action required", "alert", "invoice", "payment failed"]
    if any(word in subject_lower for word in urgent_subject_words):
        score += 20
        reasons.append("Subject contains aggressive/urgent phishing keywords")

    phishing_calls_to_action = ["click here", "login to your account", "verify your account", "update your details"]
    if any(phrase in body_lower for phrase in phishing_calls_to_action):
        score += 20
        reasons.append("Body contains suspicious requests for user action")

    # --- לוגיקת אימות (SPF / DKIM)  ---
    if headers:
        headers_lower = headers.lower()
        if "spf=pass" in headers_lower and "dkim=pass" in headers_lower:
            print("[*] Email Passed SPF & DKIM Validation. Halving the score to prevent False Positive.")
            score = score // 2  # חותך את הציון בחצי!
            reasons.append("Verified Sender: Email passed standard cryptographic authentication (SPF/DKIM)")

    score = min(score, 100)

    if score >= 70:
        verdict = "High Risk"
    elif score >= 30:
        verdict = "Medium Risk"
    else:
        verdict = "Safe"
        reasons.append("No suspicious indicators found")

    return {"score": score, "verdict": verdict, "reasons": reasons}