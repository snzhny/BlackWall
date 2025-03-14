import time
import os
import asyncio
import threading
from log_processor import process_log_line
from pystray import Icon, MenuItem, Menu
from PIL import Image
from attack_visualizer import run_visualization

def check_file_exists(file_path):
    """Проверяет, существует ли файл по указанному пути"""
    return os.path.exists(file_path)

def create_icon():
    """Создаёт иконку в системном трее"""
    image = Image.open("resources/tray_icon.png")
    return Icon("LogMonitor", image, "Log Monitor", Menu(MenuItem("Выход", exit_program)))

def exit_program(icon, item):
    """Остановка программы"""
    icon.stop()

async def tail_log(server, log_file):
    if not check_file_exists(log_file):
        print(f"❌ Файл {log_file} не найден!")
        return

    print(f"🟢 Мониторинг логов: {log_file}")

    with open(log_file, "r", encoding="utf-8") as file:
        file.seek(0, os.SEEK_END)

        while True:
            line = file.readline()
            if line:
                print(f"📜 Новая строка в логе: {line.strip()}")
                await asyncio.to_thread(process_log_line, server, line.strip())
            else:
                await asyncio.sleep(0.1)  # Уменьшил задержку для более быстрого чтения


def start_monitoring(server, log_file):
    """Запускает мониторинг логов и визуализацию"""
    icon = create_icon()
    icon_thread = threading.Thread(target=icon.run)
    icon_thread.daemon = True
    icon_thread.start()

    # ✅ Автозапуск визуализации атак
    run_visualization()

    # Запускаем асинхронную задачу
    asyncio.run(tail_log(server, log_file))