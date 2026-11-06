from flask import Flask, render_template, request
from src.analyzer import URLAnalyzer
from src.vt_client import VirusTotalClient

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
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

    return render_template('index.html', result=result, vt_result=vt_result, error=error)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)