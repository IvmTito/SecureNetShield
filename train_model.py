import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import warnings

warnings.filterwarnings('ignore')

def train_and_save_model():
    print("🚀 بدء عملية التدريب الاحترافية...")
    
    try:
        df = pd.read_csv('PhishingData.csv')
    except FileNotFoundError:
        print("❌ خطأ: ملف PhishingData.csv غير موجود!")
        return

    # تنظيف الأعمدة
    df.columns = df.columns.str.strip()

    # تجهيز البيانات
    X = df.iloc[:, 1:-1] 
    y = df.iloc[:, -1]

    # تقسيم البيانات
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # بناء النموذج
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    print("⏳ جاري تدريب النموذج...")
    model.fit(X_train, y_train)

    # التقييم
    accuracy = model.score(X_test, y_test)
    print(f"✅ تم التدريب بنجاح!")
    print(f"📊 دقة النموذج النهائية: {accuracy * 100:.2f}%")

    # الحفظ
    joblib.dump(model, 'phishing_model.pkl')
    print("💾 تم حفظ النموذج في ملف 'phishing_model.pkl'")

if __name__ == "__main__":
    train_and_save_model()