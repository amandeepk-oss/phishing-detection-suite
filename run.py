from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from src.analyzer import URLAnalyzer
from src.vt_client import VirusTotalClient
from src.database import init_db, save_scan, get_recent_scans, create_user, verify_user
from pypdf import PdfReader
import re

app = Flask(__name__)
app.secret_key = 'super_secret_phishing_detector_key'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    # Simple user loader based on session ID
    # In production, fetch from DB by ID. For now, recreate user object.
    return User(user_id, "user")

# Database initialize karein jab app start ho
init_db()

latest_scan_result = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user_data = verify_user(username, password)
        if user_data:
            user = User(str(user_data['id']), user_data['username'])
            login_user(user)
            return redirect(url_for('index'))
        else:
            error = "Invalid username ya password."
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            error = "Username aur password dono zaroori hain."
        else:
            created = create_user(username, password)
            if created:
                success = "Account successfully ban gaya! Ab aap login kar sakte hain."
            else:
                error = "Yeh username pehle se exist karta hai."
    return render_template('signup.html', error=error, success=success)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    global latest_scan_result
    result = None
    vt_result = None
    error = None

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            error = "Kripya ek valid URL enter karein."
        else:
            analyzer = URLAnalyzer(url)
            resolved_url = analyzer.clean_and_resolve_url()
            result = analyzer.run_heuristics()
            
            vt_client = VirusTotalClient()
            vt_result = vt_client.check_url(resolved_url)

            latest_scan_result = {
                "heuristic": result,
                "virustotal": vt_result
            }

            status = result.get('status', 'Unknown')
            risk_score = result.get('risk_score', 0)
            save_scan(url, status, risk_score)

    recent_scans = get_recent_scans()
    return render_template('index.html', result=result, vt_result=vt_result, error=error, recent_scans=recent_scans)

@app.route('/export-report', methods=['GET'])
@login_required
def export_report():
    if not latest_scan_result:
        return "No scan result available to export!", 400
    
    return jsonify(latest_scan_result), 200, {
        'Content-Disposition': 'attachment; filename=phishing_scan_report.json'
    }

@app.route('/bulk-scan', methods=['GET', 'POST'])
@login_required
def bulk_scan():
    results = []
    if request.method == 'POST':
        urls_text = request.form.get('urls', '')
        urls = [u.strip() for u in urls_text.splitlines() if u.strip()]
        
        vt_client = VirusTotalClient()
        for url in urls[:10]:
            analyzer = URLAnalyzer(url)
            resolved_url = analyzer.clean_and_resolve_url()
            result = analyzer.run_heuristics()
            
            vt_result = vt_client.check_url(resolved_url)
            
            status = result.get('status', 'Unknown')
            risk_score = result.get('risk_score', 0)
            save_scan(url, status, risk_score)
            
            results.append({
                "url": url,
                "status": status,
                "risk_score": risk_score,
                "malicious": vt_result.get('malicious', 0) if vt_result else 0
            })
            
    return render_template('bulk.html', results=results)

@app.route('/pdf-scan', methods=['GET', 'POST'])
@login_required
def pdf_scan():
    scan_results = []
    error = None
    if request.method == 'POST':
        if 'pdf_file' not in request.files:
            error = "Kripya ek file select karein."
        else:
            file = request.files['pdf_file']
            if file.filename == '':
                error = "Koi file choose nahi ki gayi."
            elif file and file.filename.lower().endswith('.pdf'):
                try:
                    reader = PdfReader(file)
                    text = ""
                    for page in reader.pages:
                        text += page.extract_text() or ""
                    
                    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
                    extracted_urls = list(set(url_pattern.findall(text)))
                    
                    vt_client = VirusTotalClient()
                    for url in extracted_urls[:5]:
                        analyzer = URLAnalyzer(url)
                        resolved_url = analyzer.clean_and_resolve_url()
                        res = analyzer.run_heuristics()
                        vt_res = vt_client.check_url(resolved_url)
                        
                        scan_results.append({
                            "url": url,
                            "status": res.get('status'),
                            "risk_score": res.get('risk_score'),
                            "malicious": vt_res.get('malicious', 0) if vt_res else 0
                        })
                    if not extracted_urls:
                        error = "Is PDF ke andar koi bhi URL nahi mila."
                except Exception as e:
                    error = f"PDF read karne mein error aayi: {str(e)}"
            else:
                error = "Kripya sirf valid .pdf file upload karein."
                
    return render_template('pdf.html', scan_results=scan_results, error=error)

@app.route('/email-analyzer', methods=['GET', 'POST'])
@login_required
def email_analyzer():
    analysis = None
    error = None
    if request.method == 'POST':
        headers_text = request.form.get('headers', '').strip()
        if not headers_text:
            error = "Kripya email headers paste karein."
        else:
            analysis = {
                "spf": "Pass" if "spf=pass" in headers_text.lower() else "Fail/Not Found",
                "dkim": "Pass" if "dkim=pass" in headers_text.lower() else "Fail/Not Found",
                "dmarc": "Pass" if "dmarc=pass" in headers_text.lower() else "Fail/Not Found",
                "suspicious": False
            }
            if "spf=fail" in headers_text.lower() or "dmarc=fail" in headers_text.lower():
                analysis["suspicious"] = True
                
    return render_template('email_analyzer.html', analysis=analysis, error=error)

@app.route('/api/v1/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Kripya JSON body mein 'url' provide karein."}), 400
    
    url = data['url'].strip()
    if not url:
        return jsonify({"error": "URL empty nahi ho sakta."}), 400
        
    analyzer = URLAnalyzer(url)
    resolved_url = analyzer.clean_and_resolve_url()
    result = analyzer.run_heuristics()
    
    vt_client = VirusTotalClient()
    vt_result = vt_client.check_url(resolved_url)
    
    status = result.get('status', 'Unknown')
    risk_score = result.get('risk_score', 0)
    save_scan(url, status, risk_score)
    
    return jsonify({
        "url": url,
        "resolved_url": resolved_url,
        "heuristics": result,
        "virustotal": vt_result
    }), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)