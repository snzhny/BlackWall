import matplotlib.pyplot as plt
import matplotlib.animation as animation
import threading
import time
from collections import defaultdict
import json
import os

# Глобальный словарь для хранения атак по IP и типам атак
attack_data = defaultdict(lambda: defaultdict(int))
# Словарь для динамического сопоставления типов атак и цветов
attack_colors = {}
# Список доступных цветов, который будет использоваться для новых типов атак
available_colors = ['red', 'blue', 'green', 'orange', 'purple', 'cyan', 'magenta', 'brown']

DATA_FILE = "attack_data.json"

def update_attack_data(ip, attack_type):
    global attack_data
    attack_data[ip][attack_type] += 1  # Теперь ошибки не будет!
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                data = json.load(f)
                # Если данные не словарь, то переинициализируем
                if not isinstance(data, dict):
                    data = {}
            except Exception as e:
                print(f"[ERROR] Не удалось загрузить данные: {e}")
                data = {}
            attack_data = data
    else:
        attack_data = {}

    # Если для данного IP нет записи или она не словарь – создаём словарь
    if ip not in attack_data or not isinstance(attack_data[ip], dict):
        attack_data[ip] = {}

    # Обновляем счётчик для типа атаки
    if attack_type in attack_data[ip]:
        attack_data[ip][attack_type] += 1
    else:
        attack_data[ip][attack_type] = 1

    with open(DATA_FILE, "w") as f:
        json.dump(attack_data, f, indent=4)
    run_visualization()
    print(f"🔥 Данные обновлены: {attack_data}")


def animate(i):
    plt.cla()  # Очистка графика

    labels = []
    counts = []
    colors = []

    # Формируем списки для меток, значений и цветов
    for ip, attacks in attack_data.items():
        for attack_type, count in attacks.items():
            label = f"{ip} - {attack_type}"
            labels.append(label)
            counts.append(count)
            # Если такого типа атаки еще нет в attack_colors, назначаем ему цвет
            if attack_type not in attack_colors:
                attack_colors[attack_type] = available_colors[len(attack_colors) % len(available_colors)]
            colors.append(attack_colors[attack_type])

    plt.barh(labels, counts, color=colors)
    plt.xlabel("Количество атак")
    plt.ylabel("IP и тип атаки")
    plt.title("Визуализация атак в реальном времени")
    plt.xticks(rotation=45)

def start_visualization():
    """Запускает графическое окно с динамическим графиком атак."""
    print("🟢 Запуск визуализации атак...")
    fig = plt.figure(figsize=(10, 6))
    ani = animation.FuncAnimation(fig, animate, interval=1000)  # Обновление каждую секунду

    while True:
        plt.pause(0.1)  # Даём время на обновление данных

def run_visualization():
    """Запускает визуализацию в отдельном потоке."""
    vis_thread = threading.Thread(target=start_visualization, daemon=True)
    vis_thread.start()

if __name__ == "__main__":
    run_visualization()

    # Тестовый поток обновления данных
    for i in range(5):
        update_attack_data("192.168.1.1", "DDoS")
        time.sleep(2)
        update_attack_data("192.168.1.1", "SQL Injection")
        time.sleep(2)
        update_attack_data("192.168.1.2", "Brute Force")
        time.sleep(2)
