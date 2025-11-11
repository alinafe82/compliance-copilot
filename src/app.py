from fastapi import FastAPI
from pydantic import BaseModel
from .llm import get_llm
from .safety import mask_pii, SYSTEM_PROMPT
from .scoring import score_risk

app = FastAPI(title="Compliance Copilot")

class PRPayload(BaseModel):
    title: str
    body: str
    diff: str

class TicketPayload(BaseModel):
    summary: str
    description: str

@app.post("/analyze/pr")
def analyze_pr(pr: PRPayload):
    text = f"{pr.title}\n{pr.body}\n{pr.diff}"
    sanitized = mask_pii(text)
    llm = get_llm()
    prompt = f"{SYSTEM_PROMPT}\nTask: Provide a concise risk summary and top 3 actions.\nInput:\n{sanitized}"
    result = llm.complete(prompt)
    risk = score_risk(result)
    return {"summary": result, "risk_score": risk}

@app.post("/analyze/ticket")
def analyze_ticket(t: TicketPayload):
    text = f"{t.summary}\n{t.description}"
    sanitized = mask_pii(text)
    llm = get_llm()
    prompt = f"{SYSTEM_PROMPT}\nTask: Provide likely severity, blast radius, and next steps.\nInput:\n{sanitized}"
    result = llm.complete(prompt)
    risk = score_risk(result)
    return {"summary": result, "risk_score": risk}
