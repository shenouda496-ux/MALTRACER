import tkinter as tk
from tkinter.scrolledtext import ScrolledText


def show_alert(subject, sender, risk, classification, reasons, urls):
    root = tk.Tk()
    root.title("MalTracer Security Alert")
    root.geometry("800x800")
    root.configure(bg="#1e1e1e")
    root.attributes("-topmost", True)

    title = tk.Label(
        root,
        text="POTENTIALLY MALICIOUS EMAIL DETECTED",
        bg="#1e1e1e",
        fg="#ff4d4d",
        font=("Segoe UI", 16, "bold")
    )
    title.pack(pady=15)

    info = (
        "DO NOT open this email.\n"
        "DO NOT click any links or download attachments.\n\n"
        f"Classification: {classification}\n"
        f"Risk Score: {risk}\n"
        f"From: {sender}\n"
        f"Subject: {subject}"
    )

    info_label = tk.Label(
        root,
        text=info,
        bg="#1e1e1e",
        fg="white",
        justify="left",
        anchor="w",
        font=("Segoe UI", 11)
    )
    info_label.pack(fill="x", padx=20)

    tk.Label(
        root,
        text="Detection Reasons",
        bg="#1e1e1e",
        fg="#ffcc00",
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", padx=20, pady=(20, 5))

    reasons_box = ScrolledText(root, height=6)
    reasons_box.pack(fill="x", padx=20)

    if reasons:
        for r in reasons:
            reasons_box.insert("end", f"• {r}\n")
    else:
        reasons_box.insert("end", "No reasons available.")

    reasons_box.config(state="disabled")

    tk.Label(
        root,
        text="Suspicious URLs - DO NOT OPEN",
        bg="#1e1e1e",
        fg="#ff6666",
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", padx=20, pady=(20, 5))

    urls_box = ScrolledText(root, height=8)
    urls_box.pack(fill="both", expand=True, padx=20)

    if urls:
        for u in urls:
            urls_box.insert("end", f"⚠ {u}\n\n")
    else:
        urls_box.insert("end", "No URLs found.")

    urls_box.config(state="disabled")

    tk.Button(
        root,
        text="Dismiss Alert",
        command=root.destroy,
        bg="#cc0000",
        fg="white",
        font=("Segoe UI", 11, "bold")
    ).pack(pady=20)

    root.mainloop()