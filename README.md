# EmailShield 🛡️
### A real-time Gmail Add-on that leverages a multi-layered defense model to analyze opened emails, delivering a maliciousness score and a clear, explainable security verdict.

## 🧠 Security Logic & Core Features

The system evaluates each email through a strict, rule-based pipeline:

### 1. SQLite Blacklist Engine (Priority Check)
Before external APIs are queried, the system checks the sender's address against a local **SQLite** database. 
* If a match is found in the manually managed blacklist, the scan terminates immediately, assigns a **100/100 Threat Score**, and flags the email as `Blacklisted`.

### 2. Google Safe Browsing Integration
The system extracts all URLs from the email body and verifies them against Google's global threat database. Any known malicious link results in an immediate **100/100 Threat Score**.

### 3. Domain Maturity (RDAP Protocol) & Subdomain Extraction
Analyzes the sender's domain age to detect freshly registered "look-alike" domains commonly used in phishing campaigns. The system uses `tldextract` to smartly isolate the root domain, ensuring enterprise subdomains (e.g., `accounts.google.com`) don't break the scan.
* **Domain < 4 days old:** +90 points (Critical)
* **Domain < 30 days old:** +50 points (Suspicious)
* **Established domains:** 0 points

### 4. Authentication Verification (SPF/DKIM) - False Positive Reduction
To prevent legitimate security alerts from being flagged as malicious, the system parses the hidden `Authentication-Results` headers. If an email passes standard cryptographic authentication (SPF/DKIM) and comes from an established domain, its final risk score is **reduced by 50%**.

### 5. Heuristic Analysis
Scans the subject and body for aggressive social engineering keywords (e.g., "Urgent", "Action Required") and suspicious call-to-action phrases.

### 6. Scan Data & Audit Logging
Every evaluated email is automatically logged into the SQLite database. The system records the sender's details, the final threat score, the verdict, and the specific risk factors identified, providing a comprehensive audit trail for security review.

---

## 🏗️ System Architecture

**Backend (FastAPI on Render):** The central orchestrator of the system. It handles secure HTTP requests from Gmail, manages asynchronous API calls (RDAP, Safe Browsing), interacts with the SQLite database, and computes the final threat score.

**Frontend (Gmail Add-on):** Built with Google Apps Script, the frontend integrates directly into the Gmail UI. It extracts email metadata, communicates with the backend, and renders a dynamic, color-coded security card based on the results.

---

## 🧪 Testing the System (Demo Mode)
To demonstrate the system's "High Risk" UI and response logic:
1. Send an email to the connected Gmail account with the word **"DEMO"** in the subject line.
2. Open the email and trigger the Add-on.
3. The backend will intercept the keyword, simulate a 0-day-old malicious domain, and return a **90/100 High Risk** verdict with red visual indicators and a direct link to this GitHub repository.

---

## 💡 Engineering Notes
* **The Subdomain Problem:** One of the core challenges addressed was domain age verification for massive organizations. Emails sent from subdomains naturally fail standard RDAP checks because registries only track root domains. MailShield implements an extraction layer to cleanly parse the root domain before querying, preventing False Positives on legitimate enterprise emails.
* **RDAP over WHOIS:** I migrated from traditional WHOIS to RDAP for domain checks. RDAP returns clean JSON and is much more stable on cloud platforms (like Render), avoiding the rate limits and connection drops common with legacy WHOIS servers.
* **Demo Environment (Blacklist):** The local SQLite blacklist is kept empty for this demo. Normally, if a sender is blacklisted, the scan stops immediately and returns a 100 score. Keeping it empty allows you to see the rest of the analysis engine at work.

## 🛠️ Tech Stack
* **Backend:** Python 3.9+, FastAPI (Deployed on Render)
* **Database:** SQLite (Lightweight, local database for Blacklist and Scan Logging)
* **Frontend:** Google Apps Script (Gmail Add-on SDK)
* **Libraries:** `tldextract`, `requests`
* **External APIs:** RDAP Protocol, Google Safe Browsing API

## ⚙️ Installation & Setup

### 1. Backend Setup (FastAPI & SQLite)
The backend is built with FastAPI and uses a local SQLite database for the blacklist and logging. 

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/danielrotman/upwind-home-assignment.git](https://github.com/danielrotman/upwind-home-assignment.git)
   cd upwind-home-assignment
   ```

2. **Install dependencies:**
   It is recommended to use a virtual environment.
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Variables:**
   Create a `.env` file in the root directory. You will need a Google Safe Browsing API key:
   ```env
   GOOGLE_API_KEY=your_google_api_key_here
   ```

4. **Run the local server:**
   ```bash
   uvicorn main:app --reload
   ```
   *(Note: The live demo of this project is deployed on Render. Local execution is only required for development or local testing).*

### 2. Frontend Setup (Gmail Add-on)
The frontend is a Google Apps Script that connects directly to the Gmail UI.

1. Go to [Google Apps Script](https://script.google.com/) and create a new project.
2. Clear the default code and paste the contents of the `apps_script` file from this repository.
3. **Important:** Locate the API endpoint variable in the script and update it to point to your live Render backend URL.
4. Click **Deploy** -> **Test Deployments**.
5. Select **Application: Gmail** and click **Install**. The Add-on will now appear in your Gmail sidebar when you open an email.


## 📸 Screenshots & UI

Here are a few examples of the Add-on in action, displaying different threat levels based on the analysis:

**🔴 High Risk (Simulated Demo)** - *90/100 Threat Score*

[<img width="1277" height="553" alt="Screenshot 2026-05-22 184951" src="https://github.com/user-attachments/assets/fa7c44d2-d732-41c3-97cc-b0c35f3ce5ca" />]

**🟡 Suspicious Email** - *60/100 Threat Score*

[<img width="1261" height="587" alt="Screenshot 2026-05-22 184728" src="https://github.com/user-attachments/assets/c59b2159-38e6-4597-a0e4-dcae9e34ae81" />]

**🟢 Safe Email** - *20/100 Threat Score*

[<img width="1277" height="591" alt="Screenshot 2026-05-22 184907" src="https://github.com/user-attachments/assets/61f6570a-43d4-4804-96a0-473768685713" />]
