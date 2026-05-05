#!/usr/bin/env python3
import urllib.request, json, os, threading

API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
API_URL = 'https://api.anthropic.com/v1/messages'

def analyze_threat(src_ip, alert_type, details):
    if not API_KEY:
        return 'API key no configurada'
    prompt = f'Eres un analista de ciberseguridad. Analiza esta alerta en 2-3 frases en espanol:\n'
    prompt += f'IP origen: {src_ip}\n'
    prompt += f'Tipo de alerta: {alert_type}\n'
    prompt += f'Detalles: {details}\n'
    prompt += 'Explica el riesgo y da una recomendacion concreta.'
    payload = json.dumps({
        'model': 'claude-haiku-4-5',
        'max_tokens': 200,
        'messages': [{'role': 'user', 'content': prompt}]
    }).encode('utf-8')
    req = urllib.request.Request(API_URL, data=payload, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('x-api-key', API_KEY)
    req.add_header('anthropic-version', '2023-06-01')
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data['content'][0]['text']
    except urllib.request.HTTPError as e:
        body = e.read().decode('utf-8')
        return f'Error HTTP {e.code}: {body[:100]}'
    except Exception as e:
        return f'Error: {str(e)}'

def analyze_async(src_ip, alert_type, details, callback):
    def run():
        result = analyze_threat(src_ip, alert_type, details)
        callback(result)
    t = threading.Thread(target=run, daemon=True)
    t.start()
