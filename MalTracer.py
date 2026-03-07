import threading

from monitoring.process_monitor import monitor_processes
from monitoring.network_monitor import monitor_connections
from monitoring.file_monitor import start_file_monitor


def main():

    print("[+] MALTRACER started")

    #Process Monitor
    process_thread = threading.Thread(
        target=monitor_processes,
        daemon=True
    )
    process_thread.start()

    #Network Monitor
    network_thread = threading.Thread(
        target=monitor_connections,
        daemon=True
    )
    network_thread.start()

    #File Monitor
    observer = start_file_monitor()

    observer.join()


if __name__ == "__main__":
    main()