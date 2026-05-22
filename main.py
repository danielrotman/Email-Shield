from fastapi import FastAPI
from pydantic import BaseModel
from database import init_db, is_in_blacklist, log_scan, add_to_blacklist
from analyzer import analyze_email_content
from typing import Optional

app = FastAPI(title="EmailShield Security Scorer")

init_db()

# הגדרת מבנה הנתונים שאנחנו מצפים לקבל מהג'ימייל
class EmailData(BaseModel):
    sender: str
    subject: str
    body: str
    headers: Optional[str] = ""

@app.get("/")
async def root():
    return {"message": " Backend is ALIVE!"}


@app.post("/analyze")
async def analyze_email(email: EmailData):
    # 1. בדיקת מוניטין (Database)
    if is_in_blacklist(email.sender):
        score, verdict,reasons = 100, "High Risk",["Sender is in your manual blacklist"]

    else:
        # 2. ניתוח תוכן (Analyzer)
        result = analyze_email_content(email.sender, email.subject, email.body,email.headers)
        score, verdict, reasons = result['score'], result['verdict'], result['reasons']

    #  3. למידה אוטומטית ושמירת לוג- לצורך ההדגמה הרשימה השחורה כרגע מבוטלת
    #if score >= 80:
    #   add_to_blacklist(email.sender)

    log_scan(email.sender, email.subject, score, verdict, reasons)

    return {"score": score, "verdict": verdict,"reasons": reasons}