import requests

TELEGRAM_BOT_TOKEN = ""
CHAT_ID = ""


def send_telegram_message(message=None, ip=None, attack_time=None, suspicious_url=None):
    """
    Отправляет уведомление в Telegram.

    Можно передать либо готовое сообщение через параметр message,
    либо задать ip, attack_time и suspicious_url, которые будут автоматически объединены в сообщение.
    """
    if not message:
        parts = []
        if ip:
            parts.append(f"IP: {ip}")
        if attack_time:
            parts.append(f"Время атаки: {attack_time}")
        if suspicious_url:
            parts.append(f"Подозрительный URL: {suspicious_url}")
        message = "\n".join(parts)

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}

    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("✅ Уведомление отправлено в Telegram")
        else:
            print(f"❌ Ошибка при отправке уведомления: {response.text}")
    except Exception as e:
        print(f"⚠ Ошибка соединения с Telegram: {e}")
