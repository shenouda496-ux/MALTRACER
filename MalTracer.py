import threading
import queue

from monitoring.process_monitor import monitor_processes
from monitoring.network_monitor import monitor_connections
from monitoring.file_monitor import start_file_monitor
from detection_engine.engine import DetectionEngine
from logging_system.logger import log_event
import logging_system.logger as edr_logger
import os
import subprocess
import logging


def process_event_queue(event_queue, engine):
    while True:
        event = event_queue.get()
        result_event = engine.process_event(event)
        log_event(result_event)


def main():

    print("[+] MALTRACER started")
    
    event_queue = queue.Queue()
    engine = DetectionEngine()

    # Event Processing Thread
    processing_thread = threading.Thread(
        target=process_event_queue,
        args=(event_queue, engine),
        daemon=True
    )
    processing_thread.start()

    #Process Monitor
    process_thread = threading.Thread(
        target=monitor_processes,
        args=(event_queue.put,),
        daemon=True
    )
    process_thread.start()

    #Network Monitor
    network_thread = threading.Thread(
        target=monitor_connections,
        args=(event_queue.put,),
        daemon=True
    )
    network_thread.start()

    #File Monitor
    observer = start_file_monitor(callback=event_queue.put)

    observer.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")
    finally:
        print("\n[*] Shutting down MALTRACER gracefully...")
        logging.shutdown()  # Release file locks before mail.go reads the json attachment
        log_file = edr_logger.CURRENT_LOG_FILE
        if log_file and os.path.exists(log_file):
            print(f"[*] Dispatching final log file ({log_file}) to administrator via Go Mailer...")
            try:
                base_dir = os.path.dirname(__file__)
                mail_go = os.path.join(base_dir, "mail.go")
                subject = "[MALTRACER NOTIFICATION] EDR Session Terminated"
                body = "MALTRACER has been stopped. Attached is the full JSON log history for this session."
                subprocess.run(["go", "run", mail_go, subject, body, log_file], capture_output=False, cwd=base_dir)
                print("[+] Dispatch Complete. Goodbye.")
            except Exception as e:
                print(f"[-] Failed to dispatch logs: {e}")
        else:
            print("[-] No logs produced to send.")