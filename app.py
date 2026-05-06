from flask import Flask, request, jsonify
import lightgbm as lgb
import numpy as np
import os
from flask_cors import CORS
import json

app = Flask(__name__)

# ================== CORS cho Chrome Extension ==================
CORS(app, resources={
    r"/*": {
        "origins": "*",                    # Cho phép tất cả Chrome Extension
        "allow_headers": ["Content-Type"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": True
    }
})

# Đường dẫn model (có thể dùng biến môi trường)
base_path = os.path.dirname(os.path.abspath(__file__))
model_path = os.getenv('MODEL_PATH', os.path.join(base_path, 'detect_html_model.txt'))

# Load model một lần khi khởi động
try:
    model = lgb.Booster(model_file=model_path)
    print(f"✅ Model loaded successfully from: {model_path}")
except Exception as e:
    print(f"❌ Lỗi load model: {e}")
    model = None

# Whitelist (tạm thời lưu trong RAM + file để không mất khi restart)
WHITELIST_FILE = os.path.join(base_path, 'whitelist.json')
whitelist = set()

# Load whitelist từ file nếu có
if os.path.exists(WHITELIST_FILE):
    try:
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            whitelist = set(json.load(f))
        print(f"✅ Loaded {len(whitelist)} URLs from whitelist")
    except:
        pass

def save_whitelist():
    try:
        with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
            json.dump(list(whitelist), f)
    except:
        pass

@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({'error': 'Model chưa load được'}), 500

    try:
        data = request.get_json(force=True)
        url = data.get('url')

        # Kiểm tra whitelist
        if url in whitelist:
            return jsonify({'malicious': False, 'score': 0.0, 'whitelisted': True})

        # Trích xuất 8 đặc trưng (thêm kiểm tra lỗi)
        required = ['html_len', 'num_scripts', 'num_iframes', 'has_eval',
                    'has_atob', 'has_unescape', 'num_suspicious_events', 'entropy_char']
        if not all(k in data for k in required):
            return jsonify({'error': 'Thiếu một số đặc trưng'}), 400

        features = [
            float(data['html_len']),
            float(data['num_scripts']),
            float(data['num_iframes']),
            float(data['has_eval']),
            float(data['has_atob']),
            float(data['has_unescape']),
            float(data['num_suspicious_events']),
            float(data['entropy_char'])
        ]

        # Dự đoán
        score = model.predict([features])[0]
        is_malicious = bool(score > 0.7)

        return jsonify({
            'malicious': is_malicious,
            'score': float(score),
            'url': url
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/report-safe', methods=['POST'])
def report_safe():
    try:
        data = request.get_json(force=True)
        url = data.get('url')
        if url:
            whitelist.add(url)
            save_whitelist()
            return jsonify({'status': 'added_to_whitelist', 'url': url})
        return jsonify({'error': 'Không có URL'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# Health check (kiểm tra server có chạy không)
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model is not None,
        'whitelist_size': len(whitelist)
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
