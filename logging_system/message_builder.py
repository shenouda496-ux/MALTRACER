def build_message(event):

    event_type = event.get("event_type")

    # =========================
    # Network Events
    # =========================

    if event_type == "network_connection":

        process = event.get("process_name")
        pid = event.get("pid")
        dst_ip = event.get("dst_ip")
        dst_port = event.get("dst_port")

        return f"Process {process} (PID {pid}) opened outbound network connection to {dst_ip}:{dst_port}"

    # =========================
    # Process Events
    # =========================

    elif event_type == "process_started":

        process = event.get("process_name")
        pid = event.get("pid")
        parent = event.get("parent_pid")
        path = event.get("process_path")

        return f"Process {process} started (PID {pid}, Parent {parent}) from {path}"

    # =========================
    # File Events
    # =========================

    elif event_type == "executable_created":

        path = event.get("destination")

        return f"Executable created at {path}"

    elif event_type == "executable_deleted":

        path = event.get("source")

        return f"Executable deleted from {path}"

    elif event_type == "executable_modified":

        path = event.get("source")

        return f"Executable modified at {path}"

    elif event_type == "executable_moved":

        src = event.get("source")
        dst = event.get("destination")

        return f"Executable moved from {src} to {dst}"

    return "Unknown event"