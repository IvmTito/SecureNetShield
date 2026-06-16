import pandas as pd
import re
import urllib.parse
import socket
import ssl
import requests
from bs4 import BeautifulSoup
import joblib
import warnings
warnings.filterwarnings('ignore')

REQUEST_TIMEOUT = 5

class PhishingDetector:
    def __init__(self):
        print("🤖 جاري تحميل النموذج الذكي...")
        self.model = joblib.load('phishing_model.pkl')
        print("✅ تم تحميل النموذج.\n")

    def get_url_features(self, url):
        """ تحليل الرابط ثابت (Static URL Analysis) """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        
        features = []

        # 1. having_IP_Address
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features.append(-1 if re.search(ip_pattern, domain) else 1)

        # 2. URL_Length
        length = len(url)
        if length < 54: features.append(1)
        elif 54 <= length <= 75: features.append(0)
        else: features.append(-1)

        # 3. Shortining_Service
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
        features.append(-1 if any(s in url for s in shorteners) else 1)

        # 4. having_At_Symbol (خطر جداً)
        features.append(-1 if '@' in url else 1)

        # 5. double_slash_redirecting
        features.append(-1 if '//' in url[7:] else 1)

        # 6. Prefix_Suffix
        features.append(-1 if '-' in domain else 1)

        # 7. having_Sub_Domain
        dots = domain.count('.')
        if dots == 1: features.append(1)
        elif dots == 2: features.append(0)
        else: features.append(-1)

        return features, parsed

    def get_content_features(self, url, parsed):
        """ تحليل محتوى الموقع (Dynamic Content Analysis) """
        features_content = []
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 8. SSLfinal_State
            try:
                context = ssl.create_default_context()
                with socket.create_connection((parsed.netloc, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                        cert = ssock.getpeercert()
                        features_content.append(1) 
            except:
                features_content.append(-1) 

            # 9. Domain_registeration_length
            features_content.append(0)

            # 10. Favicon
            features_content.append(1)

            # 11. port
            features_content.append(1)

            # 12. HTTPS_token
            if 'https' in parsed.scheme: features_content.append(1)
            else: features_content.append(-1)

            # 13. Request_URL
            features_content.append(1)

            # 14. URL_of_Anchor
            anchors = soup.find_all('a')
            total_anchors = len(anchors)
            if total_anchors == 0: features_content.append(1)
            else:
                anchor_tags_count = sum(1 for a in anchors if a.get('href', '').startswith('#'))
                ratio = anchor_tags_count / total_anchors
                if ratio > 0.31: features_content.append(-1)
                else: features_content.append(0)

            # 15. Links_in_tags
            meta_links = len(soup.find_all('link', rel=True))
            script_links = len(soup.find_all('script', src=True))
            total_links = meta_links + script_links
            if total_links > 10: features_content.append(-1)
            elif total_links > 0: features_content.append(0)
            else: features_content.append(1)

            # 16. SFH
            forms = soup.find_all('form')
            if not forms: features_content.append(1)
            else:
                action = forms[0].get('action', '')
                if action == '' or action == 'about:blank': features_content.append(-1)
                else:
                    if parsed.netloc in action: features_content.append(1)
                    else: features_content.append(0)

            # 17. Submitting_to_email
            forms_str = str(forms)
            features_content.append(-1 if 'mailto:' in forms_str else 1)

            # 18. Abnormal_URL
            features_content.append(1)

            # 19. Redirect
            if len(response.history) > 0: features_content.append(-1)
            else: features_content.append(1)

            # 20. on_mouseover
            scripts = soup.find_all('script')
            mouseover_found = any('onmouseover' in str(s) for s in scripts)
            features_content.append(-1 if mouseover_found else 1)

            # 21. RightClick
            rightclick_found = any('contextmenu' in str(s) for s in scripts)
            features_content.append(-1 if rightclick_found else 1)

            # 22. popUpWidnow
            popup_found = any('window.open' in str(s) for s in scripts)
            features_content.append(-1 if popup_found else 1)

            # 23. Iframe
            if soup.find('iframe'): features_content.append(-1)
            else: features_content.append(1)

        except Exception as e:
            # لو فشل الاتصال
            # هنعتبر SSL خطأ (-1) وباقي الأشياء مشبوهة (0)
            features_content.append(-1) # SSL Failed
            for _ in range(15): features_content.append(0)

        # باقي الخصائص (معلومات خارجية)
        for _ in range(7): features_content.append(1)

        return features_content

    def check_heuristic_rules(self, url, features):
        """
        قواعد أمنية صارمة (Heuristic Rules).
        لو وجدنا علامات خطأ قاتلة، نلغي رأي النموذج.
        """
        # القاعدة 1: وجود علامة @ في الرابط (مؤشر قوي جداً للتصيد)
        # features[3] هو الـ index لعلامة @
        if features[3] == -1:
            return "CRITICAL: Found '@' symbol", 99.99
        
        # القاعدة 2: الرابط عبارة عن IP مباشر
        if features[0] == -1:
            return "CRITICAL: Direct IP Address", 95.0
            
        # القاعدة 3: رابط طويل جداً (أكثر من 75 حرف)
        if features[1] == -1:
            return "WARNING: Suspicious Long URL", 70.0

        return None, 0

    def predict(self, url):
        # 1. تحليل الرابط
        url_feats, parsed = self.get_url_features(url)
        
        # 2. فحص القواعد الصارمة (Heuristics) قبل النموذج
        rule_msg, rule_conf = self.check_heuristic_rules(url, url_feats)
        if rule_msg:
            return -1, [1.0, 0.0], rule_msg # إجباري: Phishing
        
        # 3. تحليل المحتوى
        content_feats = self.get_content_features(url, parsed)
        
        # 4. الدمج
        final_features = url_feats + content_feats
        
        # 5. التحويل والتحليل
        df_temp = pd.read_csv('PhishingData.csv')
        df_temp.columns = df_temp.columns.str.strip()
        feature_names = df_temp.columns[1:-1]
        
        input_data = pd.DataFrame([final_features], columns=feature_names)
        
        prediction = self.model.predict(input_data.values)
        proba = self.model.predict_proba(input_data.values)
        
        return prediction[0], proba[0], None

# --- واجهة المستخدم ---
if __name__ == "__main__":
    detector = PhishingDetector()
    
    while True:
        url_input = input("\n🔗 أدخل الرابط للفحص (اكتب 'exit' للخروج): ").strip()
        if url_input.lower() == 'exit':
            print("مع السلامة!")
            break
        
        if not url_input:
            continue

        print("⏳ جاري الفحص العميق...")
        result, confidence, rule_violation = detector.predict(url_input)
        
        if result == -1:
            print(f"🚨 **PHISHING DETECTED**")
            if rule_violation:
                print(f"💡 السبب: {rule_violation}")
            print(f"نسبة الثقة: {confidence[0]*100:.2f}%")
        else:
            print(f"✅ **SAFE WEBSITE**")
            print(f"نسبة الثقة: {confidence[1]*100:.2f}%")