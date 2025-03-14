import re
import subprocess
import pickle
import os
from bot_detector import process_log_line_for_bots
import sys
import sklearn.tree
from collections import defaultdict
from datetime import datetime, timedelta
from telegram_notifier import send_telegram_message
from attack_visualizer import update_attack_data
from urllib.parse import unquote

sys.modules['sklearn.tree.tree'] = sklearn.tree


MODEL_DIR = os.path.join("resources", "models")
with open(os.path.join(MODEL_DIR, "icmp_data.sav"), "rb") as f:
    icmp_model = pickle.load(f)
with open(os.path.join(MODEL_DIR, "tcp_syn_data.sav"), "rb") as f:
    tcp_syn_model = pickle.load(f)
with open(os.path.join(MODEL_DIR, "udp_data.sav"), "rb") as f:
    udp_model = pickle.load(f)

# Паттерны для обнаружения SQL-инъекций
SQL_INJECTION_PATTERNS = [
    r"(union\s+select)",
    r"('|\")\s*(or|and)\s*\d+\s*=\s*\d+",
    r"(select\s+\*\s+from)"
]

# Глобальные переменные для контроля частоты запросов
ip_request_count = defaultdict(int)
ip_request_time = defaultdict(lambda: datetime.min)
MAX_REQUESTS_PER_MINUTE = 100  # Порог запросов на минуту


def is_sql_injection(log_line):
    """Проверяет, содержит ли строка попытку SQL-инъекции."""
    # Декодирование URL-кодировки
    decoded_line = unquote(log_line)
    print(f"[DEBUG] Проверка SQL-инъекции в: {decoded_line}")
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, decoded_line, re.IGNORECASE):
            print(f"[DEBUG] Найден паттерн SQL-инъекции: {pattern}")
            return True
    return False


def block_ip(ip):
    """Блокирует IP через Windows Firewall (входящий и исходящий трафик)."""
    print(f"🚨 Попытка блокировки IP: {ip}")

    try:
        # Удаляем старые правила, чтобы не было дубликатов
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=BlockIP_{ip}"], check=False)
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name=BlockIP_{ip}_out"], check=False)

        # Добавляем новое правило для входящего трафика
        result_in = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=BlockIP_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
            check=True, capture_output=True, text=True
        )

        # Добавляем новое правило для исходящего трафика
        result_out = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=BlockIP_{ip}_out", "dir=out", "action=block", f"remoteip={ip}"],
            check=True, capture_output=True, text=True
        )

        print(f"✅ IP {ip} успешно заблокирован!\n{result_in.stdout}\n{result_out.stdout}")

    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка при блокировке IP: {e}\nВывод ошибки: {e.stderr}")

def extract_features_for_model(log_line, protocol):
    """
    Преобразует строку лога в вектор признаков для модели.
    Пример: длина строки, количество цифр и сумма числовых частей IP.
    """
    ip = log_line.split()[0]
    length = len(log_line)
    digits = sum(c.isdigit() for c in log_line)
    ip_parts = ip.split(".")
    if len(ip_parts) == 4:
        ip_sum = sum(int(part) for part in ip_parts)
    else:
        ip_sum = 0
    return [length, digits, ip_sum]


def predict_ddos(log_line):
    log_line_lower = log_line.lower()
    features = extract_features_for_model(log_line, "generic")  # Запрос как обычный лог
    print(f"Debug: generic features = {features}")  # Добавляем отладку

    if "icmp" in log_line_lower:
        prediction = icmp_model.predict([features])
    elif "tcp" in log_line_lower and "syn" in log_line_lower:
        prediction = tcp_syn_model.predict([features])
    elif "udp" in log_line_lower:
        prediction = udp_model.predict([features])
    else:
        prediction = [0]  # Если протокол не определен, считаем, что атаки нет

    print(f"📊 ML Prediction: {prediction[0]}")
    return prediction[0]


def check_request_frequency(ip):
    global ip_request_count, ip_request_time

    current_time = datetime.now()
    time_diff = 0  # Инициализируем переменную, чтобы избежать ошибки

    if ip in ip_request_time:
        time_diff = (current_time - ip_request_time[ip]).total_seconds()
        if time_diff < 60:  # Если запросы за последнюю минуту
            ip_request_count[ip] += 1
        else:
            ip_request_count[ip] = 1  # Сброс, если прошло больше минуты
    else:
        ip_request_count[ip] = 1
        ip_request_time[ip] = current_time

    print(f"Debug: {ip} -> {ip_request_count[ip]} запросов за {time_diff:.2f} сек")

    if ip_request_count[ip] > MAX_REQUESTS_PER_MINUTE:
        print(f"🔥 DDoS-атака! IP {ip} отправил {ip_request_count[ip]} запросов!")
        return True
    return False


def process_log_line(server, log_line):
    """
    Обрабатывает строку лога:
      - Выявляет SQL-инъекции
      - Использует ML-модель для обнаружения DDoS-атак
      - При обнаружении атаки блокирует IP
      - Анализирует на наличие ботов по User-Agent
      - Проверяет частоту запросов с IP
    """
    parts = log_line.split()
    if len(parts) < 9:
        return  # Лог неполный

    ip = parts[0]
    # Объединяем часть лога, содержащую запрос. Если запрос в кавычках, то это всё равно будет строка.
    request = " ".join(parts[5:8])
    # Извлекаем время атаки и подозрительный URL из лога
    attack_time = parts[3].lstrip('[')
    suspicious_url = parts[6]

    # Проверка на SQL-инъекции (работаем с декодированным запросом)
    if is_sql_injection(request):
        print(f"⚠️ Обнаружена SQL-инъекция от {ip} в {attack_time} по URL {suspicious_url}: {request}")
        block_ip(ip)
        message = f"🚨 SQL-INJECTION! {ip} в {attack_time}. URL: {suspicious_url}"
        print(f"📤 Отправляем в Telegram: {message}")  # <-- Лог перед отправкой
        send_telegram_message(message)
        update_attack_data(ip, "SQL Injection")
    # Анализируем логи на наличие ботов (функция из bot_detector)
    process_log_line_for_bots(log_line)

    # Применяем модель для обнаружения DDoS
    prediction = predict_ddos(log_line)
    if prediction == 1:
        print(f"🔥 ML: DDoS-атака обнаружена от {ip} в {attack_time} по URL {suspicious_url}, блокируем!")
        block_ip(ip)
        send_telegram_message(f"🚨 DDoS-атака! Подозрительная активность от {ip} в {attack_time}. URL: {suspicious_url}")
        update_attack_data(ip, "DDoS")  # ✅ Без дублирования
    else:
        print(f"📊 Лог не содержит признаков DDoS-атаки от {ip} в {attack_time}. Prediction: {prediction}")

    # Проверяем частоту запросов
    if check_request_frequency(ip):
        print(f"🔥 DDoS-атака по частоте запросов от {ip} в {attack_time} по URL {suspicious_url}, блокируем!")
        block_ip(ip)
        send_telegram_message(f"🚨 DDoS-атака! Подозрительная активность от {ip} в {attack_time}. URL: {suspicious_url}")
        update_attack_data(ip, "DDoS")  # ✅ Без дублирования
