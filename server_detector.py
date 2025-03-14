import os

def detect_server():
    """Определяет, какой сервер работает (XAMPP или Nginx) и возвращает путь к логам."""
    xampp_path = r"C:\xampp\apache\logs\access.log"
    nginx_path = r"C:\nginx\logs\access.log"

    if os.path.exists(xampp_path):
        print("✅ Обнаружен XAMPP (Apache)")
        return "XAMPP", xampp_path
    elif os.path.exists(nginx_path):
        print("✅ Обнаружен Nginx")
        return "Nginx", nginx_path
    else:
        print("❌ Сервер не найден!")
        return None, None
