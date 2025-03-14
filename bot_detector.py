import re
import subprocess

# Функция для блокировки IP-адреса
def block_ip(ip_address):
    """Блокирует IP-адрес через netsh (для Windows)."""
    # try:
    #     # Команда для блокировки IP через фаервол Windows
    #     block_command = f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}'
    #     print(f"🔒 Блокировка IP: {ip_address}")
    #     subprocess.run(block_command, shell=True, check=True)
    #     print(f"🔒 IP {ip_address} заблокирован!")
    # except subprocess.CalledProcessError as e:
    #     print(f"❌ Ошибка при блокировке IP: {ip_address}. {e}")
    print("!!!! BLOCKED IP 🔒 DONT FORGET TO UNCOMMENT")

# Функция для определения, является ли User-Agent ботом
def is_bot(user_agent):
    """Проверяет, является ли User-Agent ботом."""
    bot_patterns = [
        r"python-requests",  # Боты, использующие python-requests
        r"curl",             # Боты, использующие curl
        r"wget",             # Боты, использующие wget
        r"bot",              # Общее для ботов
        r"spider",           # Спайдеры
        r"crawl",            # Краулеры
    ]
    for pattern in bot_patterns:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return True
    return False

# Обновлённая функция для анализа строки лога
def process_log_line_for_bots(log_line):
    """Обрабатывает строку лога, выявляет ботов и блокирует опасные IP-адреса."""
    try:
        ip_address = log_line.split(' ')[0]  # Первый элемент - IP-адрес
        parts = log_line.split('"')
        # Если строка корректная, предпоследний элемент содержит User-Agent
        if len(parts) >= 2:
            user_agent = parts[-2]
        else:
            user_agent = ""
    except IndexError:
        print(f"❌ Ошибка разбора строки лога: {log_line}")
        return

    if user_agent:
        if is_bot(user_agent):
            print(f"⚠️ Обнаружен опасный бот! User-Agent: {user_agent}, IP: {ip_address}")
            block_ip(ip_address)