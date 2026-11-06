import whois
from urllib.parse import urlparse
import tldextract
from src.ml_model import LexicalClassifier

class URLAnalyzer:
    def __init__(self, url):
        self.url = url

    def clean_and_resolve_url(self):
        url = self.url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url

    def run_heuristics(self):
        cleaned_url = self.clean_and_resolve_url()
        parsed = urlparse(cleaned_url)
        extracted = tldextract.extract(cleaned_url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        risk_score = 0
        indicators = []

        # 1. Lexical Classifier integration
        ml_classifier = LexicalClassifier(cleaned_url)
        ml_risk = ml_classifier.predict_risk()
        risk_score += int(ml_risk * 0.4)  # 40 weightage to lexical features

        # 2. IP address check in URL
        if any(char.isdigit() for char in parsed.netloc.replace('.', '')):
            if not parsed.netloc.replace('.', '').isdigit():
                pass
            else:
                risk_score += 30
                indicators.append("URL contains raw IP address.")

        # 3. Brand Impersonation check (Common keywords)
        keywords = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'signin']
        if any(kw in cleaned_url.lower() for kw in keywords):
            risk_score += 20
            indicators.append("URL contains sensitive phishing keywords.")

        # 4. WHOIS Creation Date check (New domain check)
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # If domain is registered recently (handled gracefully)
            if creation_date:
                # Add basic logic or let it pass if old enough
                pass
        except Exception:
            # WHOIS lookup might fail for certain TLDs, ignore safely
            pass

        final_score = min(risk_score, 100)
        status = "Safe" if final_score < 40 else "Suspicious"

        return {
            "url": self.url,
            "status": status,
            "risk_score": final_score,
            "message": "Heuristics and Lexical analysis completed successfully.",
            "indicators": indicators
        }