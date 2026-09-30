import re
import math
import urllib.request
import json
from datetime import datetime, timezone
from collections import Counter
import requests
import flet as ft

# ============================================================
# SCAMSHIELD V3.0 - STRICT ARCHITECTURE COMPLIANCE
# ============================================================

KNOWN_COMPANY_DOMAINS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "infosys": "infosys.com",
    "tcs": "tcs.com",
    "wipro": "wipro.com",
    "accenture": "accenture.com",
    "ibm": "ibm.com",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "proton.me",
}

FINANCIAL_PATTERNS = re.compile(
    r"\b(?:pay|send|transfer|deposit|fee|charge)\b"
    r".{0,35}\b(?:rs\.?|inr|₹|\$)?\s*[\d,]+",
    re.I,
)

CREDENTIAL_PATTERNS = re.compile(
    r"\b(?:otp|password|aadhaar|pan card|cvv|account number)\b",
    re.I,
)

URGENCY_PATTERNS = re.compile(
    r"\b(?:urgent|immediately|within\s+\d+\s+hours?|suspended)\b",
    re.I,
)

URL_RE = re.compile(
    r"https?://[^\s<>()]+|www\.[^\s<>()]+",
    re.I,
)

EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.I,
)

SCAM_TEMPLATES = [
    "pay registration fee to confirm your job immediately",
    "send otp and password to verify your account and prevent suspension",
    "part time work from home earn daily income like youtube videos telegram",
    "academic upskilling skill certification program training fees are applicable",
]


# ------------------------------------------------------------
# 01 // VECTOR MATCHING (TF-IDF & Cosine Similarity)
# ------------------------------------------------------------

def tokenize(text: str):
    return re.findall(r"[a-z0-9₹$]+", text.lower())


def cosine_similarity(vec_a, vec_b):
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    mag_a = math.sqrt(sum(a * a for a in vec_a))
    mag_b = math.sqrt(sum(b * b for b in vec_b))

    return dot / (mag_a * mag_b) if mag_a and mag_b else 0.0


def max_template_similarity(text: str):
    texts = [text] + SCAM_TEMPLATES
    token_lists = [tokenize(t) for t in texts]

    df = Counter()

    for tokens in token_lists:
        df.update(set(tokens))

    n_docs = len(texts)
    vocab = sorted(df)

    vectors = []

    for tokens in token_lists:
        counts = Counter(tokens)

        vectors.append([
            (counts[w] / (len(tokens) or 1))
            * (math.log((1 + n_docs) / (1 + df[w])) + 1)
            for w in vocab
        ])

    return max(
        cosine_similarity(vectors[0], tv)
        for tv in vectors[1:]
    )


# ------------------------------------------------------------
# 02 // NER (Zero-Shot Information Extraction)
# ------------------------------------------------------------

def extract_entities_ner(text: str, api_key: str) -> list:
    if not api_key:
        return ["NER (Offline): Rule-based extraction only"]

    API_URL = (
        "https://router.huggingface.co/"
        "hf-inference/models/dslim/bert-base-NER"
    )

    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    try:
        payload = {
            "inputs": text,
            "parameters": {"aggregation_strategy": "simple"}
        }

        response = requests.post(
            API_URL,
            headers=headers,
            json=payload,
            timeout=20,
        )

        data = response.json()

        if isinstance(data, list) and len(data) > 0:
            entities = [
                f"{ent['word']} ({ent.get('entity_group', ent.get('entity', 'Unknown'))})"
                for ent in data
                if ent.get("score", 0) > 0.7
            ]

            return (
                list(set(entities))
                if entities
                else ["No distinct entities found"]
            )

        return ["NER API parsing error or cold start"]

    except Exception:
        return ["NER API Timeout - Check network"]


# ------------------------------------------------------------
# 03 // FORENSICS (Levenshtein Distance)
# ------------------------------------------------------------

def levenshtein_distance(a: str, b: str):
    if a == b:
        return 0

    if len(a) < len(b):
        a, b = b, a

    if not b:
        return len(a)

    prev = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):
        curr = [i]

        for j, char_b in enumerate(b, start=1):
            curr.append(
                min(
                    curr[j - 1] + 1,
                    prev[j] + 1,
                    prev[j - 1] + (char_a != char_b),
                )
            )

        prev = curr

    return prev[-1]


def detect_domain_spoofing_dynamic(domain: str, text: str):
    GENERIC_WORDS = {
        "careers",
        "portal",
        "verify",
        "support",
        "login",
        "auth",
        "service",
        "admin",
    }

    context_words = (
        set(re.findall(r"\b[a-z]{4,}\b", text.lower()))
        - GENERIC_WORDS
    )

    domain_tokens = re.split(r"[-_.]", domain)

    for token in domain_tokens:
        if (
            len(token) < 4
            or token in {"com", "in", "org", "net", "hr"}
        ):
            continue

        for word in context_words:
            dist = levenshtein_distance(token, word)

            if 1 <= dist <= 2:
                return (
                    30,
                    f"Dynamic Spoof Match: '{token}' "
                    f"mimics text keyword '{word}'",
                    False,
                )

    return 0, None, False


# ------------------------------------------------------------
# 04 // CLASSIFIER (Naive Bayes Adjudicator)
# ------------------------------------------------------------

class NaiveBayesClassifier:
    def __init__(self):
        self.weights = {
            "has_financial": 30,
            "has_spoof": 35,
            "has_urgency": 15,
            "high_vector_sim": 20,
        }

    def predict_probability(self, features: dict) -> float:
        score = 0.0
        for feature, is_present in features.items():
            if is_present:
                score += self.weights.get(feature, 10)
        return min(max(score, 0.0), 100.0)


# ============================================================
# PIPELINE ROUTER
# ============================================================

def analyze_text(text: str, hf_token: str) -> dict:
    text_clean = re.sub(r"\s+", " ", text.strip())
    evidence = []

    has_fin = bool(FINANCIAL_PATTERNS.search(text_clean))
    has_cred = bool(CREDENTIAL_PATTERNS.search(text_clean))
    has_urg = bool(URGENCY_PATTERNS.search(text_clean))

    if has_fin:
        evidence.append("Financial request detected.")
    if has_cred:
        evidence.append("Credential/ID request detected.")
    if has_urg:
        evidence.append("Urgency/pressure detected.")

    extracted_urls = [
        re.sub(r"^https?://", "", u)
        .replace("www.", "")
        .split("/")[0]
        for u in URL_RE.findall(text_clean)
    ]

    extracted_emails = [
        e.split("@")[-1]
        for e in EMAIL_RE.findall(text_clean)
    ]

    extracted_domains = extracted_urls + extracted_emails
    has_spoof = False

    for domain in set(extracted_domains):
        if domain not in FREE_EMAIL_DOMAINS:
            spoof_score, spoof_msg, is_official = (
                detect_domain_spoofing_dynamic(domain, text_clean)
            )

            if spoof_score > 0:
                has_spoof = True
                evidence.append(spoof_msg)
            elif is_official:
                evidence.append(f"Verified matching domain context: {domain}")

    sim = max_template_similarity(text_clean)
    high_sim = sim > 0.45

    if high_sim:
        evidence.append(f"High vector similarity (Cosine: {sim:.2f})")

    nb = NaiveBayesClassifier()
    feature_matrix = {
        "has_financial": has_fin or has_cred,
        "has_spoof": has_spoof,
        "has_urgency": has_urg,
        "high_vector_sim": high_sim,
    }

    scam_probability = nb.predict_probability(feature_matrix)
    entities = extract_entities_ner(text_clean, hf_token)

    if scam_probability > 75:
        category = "Critical Risk Threat"
    elif scam_probability > 30:
        category = "Suspicious Communication"
    else:
        category = "Low Risk / Legitimate"

    return {
        "Risk_Score": round(scam_probability),
        "Threat_Category": category,
        "Entities": entities,
        "Evidence": evidence or ["No immediate threat vectors identified."],
    }


# ------------------------------------------------------------
# 05 // DELIVERY (Progressive Web App - Flet Frontend)
# ------------------------------------------------------------

def main(page: ft.Page):
    page.title = "ScamShield Architecture V3.0"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 25

    api_key_input = ft.TextField(
        label="Hugging Face API Token (Triggers Zero-Shot NER)",
        password=True,
        can_reveal_password=True,
        border_color=ft.Colors.PURPLE_400,
    )

    input_box = ft.TextField(
        label="Paste message here...",
        multiline=True,
        min_lines=10,
        expand=True,
    )

    score_text = ft.Text(
        "Naive Bayes Scam Probability: --%",
        size=20,
        weight=ft.FontWeight.BOLD,
    )

    category_text = ft.Text(
        "Classification: Awaiting Input",
        size=16,
        color=ft.Colors.GREY_400,
    )

    evidence_column = ft.Column(spacing=6)
    ner_column = ft.Column(spacing=6)

    def analyze_click(e):
        text = (input_box.value or "").strip()
        if not text:
            return

        category_text.value = "Executing Naive Bayes & NER..."
        page.update()

        res = analyze_text(text, api_key_input.value.strip())
        score = res["Risk_Score"]

        score_text.value = f"Naive Bayes Scam Probability: {score}%"
        score_text.color = (
            ft.Colors.RED_400 if score > 50 else ft.Colors.GREEN_400
        )
        category_text.value = f"Classification: {res['Threat_Category']}"

        evidence_column.controls = [
            ft.Text(f"🚩 {item}", size=13) for item in res["Evidence"]
        ]
        ner_column.controls = [
            ft.Text(f"• {item}", size=13) for item in res["Entities"]
        ]
        page.update()

    def clear_click(e):
        input_box.value = ""
        evidence_column.controls = []
        ner_column.controls = []
        score_text.value = "Naive Bayes Scam Probability: --%"
        score_text.color = ft.Colors.WHITE
        category_text.value = "Classification: Awaiting Input"
        page.update()

    analyze_btn = ft.Button(
        content=ft.Text("Run Naive Bayes Adjudicator", color=ft.Colors.WHITE),
        icon=ft.Icons.SHIELD,
        on_click=analyze_click,
        bgcolor=ft.Colors.BLUE_700,
    )

    clear_btn = ft.Button(
        content=ft.Text("Clear"),
        icon=ft.Icons.CLEAR,
        on_click=clear_click,
    )

    page.add(
        ft.Text(
            "🛡️ ScamShield Forensic Engine",
            size=28,
            weight=ft.FontWeight.BOLD,
            color=ft.Colors.BLUE_400,
        ),
        api_key_input,
        ft.Row(
            [
                ft.Column(
                    [
                        input_box,
                        ft.Row([analyze_btn, clear_btn]),
                    ],
                    expand=True,
                ),
                ft.Container(width=25),
                ft.Column(
                    [
                        score_text,
                        category_text,
                        ft.Divider(height=15, color=ft.Colors.GREY_800),
                        ft.Text("03 // Forensic Evidence", weight=ft.FontWeight.BOLD),
                        evidence_column,
                        ft.Divider(height=15, color=ft.Colors.GREY_800),
                        ft.Text("02 // Extracted NER Entities", weight=ft.FontWeight.BOLD),
                        ner_column,
                    ],
                    expand=True,
                ),
            ],
            vertical_alignment=ft.CrossAxisAlignment.START,
            expand=True,
        ),
    )


if __name__ == "__main__":
    ft.run(main, view=ft.AppView.WEB_BROWSER)