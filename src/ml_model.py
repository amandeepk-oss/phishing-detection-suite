import math
import re

class LexicalClassifier:
    def __init__(self, url):
        self.url = url

    def calculate_entropy(self, text):
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = text.count(chr(x)) / len(text)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def extract_features(self):
        features = {}
        features['url_length'] = len(self.url)
        features['count_dots'] = self.url.count('.')
        features['count_hyphens'] = self.url.count('-')
        features['count_at'] = self.url.count('@')
        features['count_digits'] = sum(c.isdigit() for c in self.url)
        features['has_ip'] = 1 if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.url) else 0
        features['entropy'] = self.calculate_entropy(self.url)
        return features

    def predict_risk(self):
        features = self.extract_features()
        score = 0
        
        # Heuristics rules combining lexical indicators
        if features['url_length'] > 75:
            score += 25
        if features['count_dots'] > 3:
            score += 20
        if features['count_hyphens'] > 2:
            score += 15
        if features['count_at'] > 0:
            score += 30
        if features['has_ip'] == 1:
            score += 40
        if features['entropy'] > 4.5:
            score += 20
            
        return min(score, 100)