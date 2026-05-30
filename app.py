import os
import jwt
import base64
import sqlite3
import anthropic
import stripe
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder='static')
CORS(app)

# ─── CONFIG ───
SECRET_KEY = os.environ.get('SECRET_KEY', 'bidcheck-secret-change-in-prod')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_PRICE_ID = os.environ.get('STRIPE_PRICE_ID')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
FREE_SCANS = 3

stripe.api_key = STRIPE_SECRET_KEY
client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

# ─── DATABASE ───
def get_db():
    db = sqlite3.connect('bidcheck.db')
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        scans_used INTEGER DEFAULT 0,
        is_pro INTEGER DEFAULT 0,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        result TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    db.commit()
    db.close()

init_db()

# ─── AUTH ───
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            db = get_db()
            user = db.execute('SELECT * FROM users WHERE id = ?', (data['user_id'],)).fetchone()
            db.close()
            if not user:
                return jsonify({'error': 'User not found'}), 401
            return f(dict(user), *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated

# ─── ROUTES ───

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    try:
        db = get_db()
        db.execute('INSERT INTO users (email, password) VALUES (?, ?)',
                   (email, generate_password_hash(password)))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        db.close()
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.utcnow() + timedelta(days=30)
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token, 'email': email, 'scans_used': 0, 'is_pro': False})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    db.close()
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid email or password'}), 401
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + timedelta(days=30)
    }, SECRET_KEY, algorithm='HS256')
    return jsonify({
        'token': token,
        'email': user['email'],
        'scans_used': user['scans_used'],
        'is_pro': bool(user['is_pro'])
    })

@app.route('/api/me', methods=['GET'])
@token_required
def me(current_user):
    return jsonify({
        'email': current_user['email'],
        'scans_used': current_user['scans_used'],
        'is_pro': bool(current_user['is_pro']),
        'free_scans_remaining': max(0, FREE_SCANS - current_user['scans_used'])
    })

@app.route('/api/scan', methods=['POST'])
@token_required
def scan(current_user):
    if not current_user['is_pro'] and current_user['scans_used'] >= FREE_SCANS:
        return jsonify({'error': 'upgrade_required', 'message': 'You have used all 3 free scans. Upgrade to BidCheck Pro for unlimited audits.'}), 402

    if 'image' not in request.json:
        return jsonify({'error': 'No image provided'}), 400

    image_data = request.json['image']
    if ',' in image_data:
        image_data = image_data.split(',')[1]

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/jpeg",
                            "data": image_data
                        }
                    },
                    {
                        "type": "text",
                        "text": """You are BidCheck, an AI that protects homeowners from contractor overcharges. Analyze this contractor quote image and provide a detailed audit.

Return your response in this exact JSON format:
{
  "contractor_type": "type of work (e.g. Roofing, HVAC, Plumbing)",
  "total_quoted": "total amount quoted",
  "overall_verdict": "FAIR | SLIGHTLY HIGH | OVERPRICED | SIGNIFICANTLY OVERPRICED",
  "overall_score": 1-10,
  "summary": "2-3 sentence plain English summary of findings",
  "line_items": [
    {
      "item": "line item name",
      "quoted_price": "price quoted",
      "fair_range": "fair market range",
      "verdict": "FAIR | HIGH | VERY HIGH",
      "note": "brief explanation"
    }
  ],
  "red_flags": ["list of concerning items or practices"],
  "negotiation_script": "exact word-for-word script the homeowner can use to negotiate",
  "estimated_savings": "estimated amount they could save by negotiating"
}

If you cannot read the quote clearly, return: {"error": "Could not read the quote clearly. Please take a clearer photo in good lighting."}

Base pricing on current US market rates. Be direct and honest — homeowners are counting on you."""
                    }
                ]
            }]
        )

        result_text = response.content[0].text
        import json
        try:
            result = json.loads(result_text)
        except:
            import re
            json_match = re.search(r'\{.*\}', result_text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                result = {"error": "Could not parse the quote. Please try a clearer photo."}

        db = get_db()
        db.execute('UPDATE users SET scans_used = scans_used + 1 WHERE id = ?', (current_user['id'],))
        db.execute('INSERT INTO scans (user_id, result) VALUES (?, ?)',
                   (current_user['id'], json.dumps(result)))
        db.commit()
        user = db.execute('SELECT * FROM users WHERE id = ?', (current_user['id'],)).fetchone()
        db.close()

        result['scans_used'] = user['scans_used']
        result['is_pro'] = bool(user['is_pro'])
        result['free_scans_remaining'] = max(0, FREE_SCANS - user['scans_used'])
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/create-checkout', methods=['POST'])
@token_required
def create_checkout(current_user):
    try:
        if not current_user.get('stripe_customer_id'):
            customer = stripe.Customer.create(email=current_user['email'])
            db = get_db()
            db.execute('UPDATE users SET stripe_customer_id = ? WHERE id = ?',
                       (customer.id, current_user['id']))
            db.commit()
            db.close()
            customer_id = customer.id
        else:
            customer_id = current_user['stripe_customer_id']

        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{'price': STRIPE_PRICE_ID, 'quantity': 1}],
            mode='subscription',
            success_url=request.host_url + 'app?upgraded=true',
            cancel_url=request.host_url + 'app',
        )
        return jsonify({'checkout_url': session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/webhook', methods=['POST'])
def webhook():
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return jsonify({'error': 'Invalid webhook'}), 400

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_id = session.get('customer')
        subscription_id = session.get('subscription')
        db = get_db()
        db.execute('UPDATE users SET is_pro = 1, stripe_subscription_id = ? WHERE stripe_customer_id = ?',
                   (subscription_id, customer_id))
        db.commit()
        db.close()

    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')
        db = get_db()
        db.execute('UPDATE users SET is_pro = 0 WHERE stripe_customer_id = ?', (customer_id,))
        db.commit()
        db.close()

    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
