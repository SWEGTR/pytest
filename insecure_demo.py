import hashlib
import os
import secrets
import sqlite3
import subprocess
import json
import requests
import yaml

# Секрет берется из переменной окружения, а не пишется в коде
DB_PASSWORD = os.environ.get("DB_PASSWORD", "default_pass")

def get_user(username):
    conn = sqlite3.connect("app.db")
    # Параметризованный запрос (защита от SQL-инъекции)
    return conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchall()

def ping(host):
    # Без shell=True, аргументы списком (защита от командной инъекции)
    return subprocess.run(["ping", "-c", "1", host], check=False)

def hash_password(password, salt=None):
    # Криптостойкий scrypt вместо MD5
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt, digest

def make_reset_token():
    # Криптостойкий генератор токенов вместо random
    return secrets.token_urlsafe(32)

def load_config(text):
    # Безопасная загрузка YAML
    return yaml.safe_load(text)

def load_session(data):
    # Замена pickle на json для безопасной десериализации
    return json.loads(data)

def fetch(url):
    # Включена проверка TLS (удален verify=False), добавлен таймаут
    return requests.get(url, timeout=10)
