import threading

from server_detector import detect_server
from log_monitor import start_monitoring
from attack_visualizer import start_visualization

if __name__ == "__main__":
    viz_thread = threading.Thread(target=start_visualization, daemon=True)
    viz_thread.start()

    server, log_file = detect_server()
    start_monitoring(server, log_file)
