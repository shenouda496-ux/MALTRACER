class RuleEngine:

    def check_condition(self, event, condition):

        cond = condition.lower().strip()

        event_type = str(event.get("event_type") or "").lower()
        p_name     = str(event.get("process_name") or "").lower()
        p_path     = str(event.get("process_path") or "").lower()
        cmd        = str(event.get("command_line") or "").lower()
        parent     = str(event.get("parent_process") or "").lower()
        dst_port   = event.get("dst_port", -1)
        dst_ip     = str(event.get("dst_ip") or "").lower()
        connections = event.get("network_connections", [])

        # Event Type
        if cond in ("network_connection", "event_type == network_connection"):
            return event_type == "network_connection"

        if cond in ("process_started", "new_process_started"):
            return event_type == "process_started"

        if cond == "file_created":
            return event_type in ("file_created", "executable_created")

        if cond == "file_modified":
            return event_type in ("file_modified", "executable_modified")

        # Process Name
        if "process_name ==" in cond:
            target = cond.split("process_name ==")[1].strip().lower()
            return p_name == target

        if "process_name in" in cond:
            try:
                names = cond.split("[")[1].split("]")[0].replace("\n", "").split(",")
                names = [n.strip().lower() for n in names]
                return p_name in names
            except Exception:
                return False

        # Parent Process
        if "parent_process ==" in cond:
            target = cond.split("parent_process ==")[1].strip().lower()
            return parent == target

        # Command Line
        if "command_line contains" in cond:
            target = cond.split("command_line contains")[1].strip().strip('"').strip("'").lower()
            return target in cmd

        # Process Path
        if "process_path contains" in cond:
            target = cond.split("contains")[1].strip().lower()
            return target in p_path

        if "process_path startswith" in cond:
            target = cond.split("startswith")[1].strip().lower()
            return p_path.startswith(target)

        # Network
        if "network_connection exists" in cond:
            return len(connections) > 0

        if "dst_port in" in cond:
            try:
                ports = cond.split("[")[1].split("]")[0].split(",")
                ports = [int(p.strip()) for p in ports if p.strip().isdigit()]
                return dst_port in ports
            except Exception:
                return False

        if "dst_ip not in local_network" in cond:
            if not dst_ip:
                return False
            local_ranges = (
                "127.", "10.", "192.168.",
                "172.16.", "172.17.", "172.18.", "172.19.",
                "172.20.", "172.21.", "172.22.", "172.23.",
                "172.24.", "172.25.", "172.26.", "172.27.",
                "172.28.", "172.29.", "172.30.", "172.31.",
            )
            return not dst_ip.startswith(local_ranges)

        # File Extension
        if "file_extension ==" in cond:
            target = cond.split("file_extension ==")[1].strip().lower()
            file_path = str(event.get("file_path") or "").lower()
            return file_path.endswith(target)

        # Built-in Flags
        if cond == "powershell_attack == true":
            return event.get("powershell_attack", False)

        if cond == "lolbin_detected == true":
            return event.get("lolbin_detected", False)

        # Unknown Process
        if cond == "unknown_process":
            trusted = {
                "svchost.exe", "explorer.exe", "services.exe",
                "lsass.exe", "winlogon.exe", "csrss.exe",
                "smss.exe", "dwm.exe", "spoolsv.exe",
                "taskhostw.exe", "sihost.exe", "ctfmon.exe",
                "searchindexer.exe", "conhost.exe", "dllhost.exe",
                "fontdrvhost.exe", "audiodg.exe", "wlanext.exe",
                "chrome.exe", "firefox.exe", "msedge.exe",
                "code.exe", "python.exe", "python3.exe",
                "node.exe", "git.exe", "maltracer.exe",
                "electron.exe", "notepad.exe", "mspaint.exe",
            }
            trusted_paths = (
                "c:\\windows\\",
                "c:\\program files\\",
                "c:\\program files (x86)\\",
            )
            return (
                event_type == "process_started"
                and p_name not in trusted
                and not any(p_path.startswith(tp) for tp in trusted_paths)
            )

        return False

    def match(self, event, rules):
        matched = []
        for rule in rules:
            keywords = rule.get("keywords", [])
            if not keywords:
                continue
            try:
                if all(self.check_condition(event, condition) for condition in keywords):
                    matched.append(rule)
            except Exception:
                continue
        return matched