import re
import datetime
import tkinter as tk
from tkinter import scrolledtext, messagebox

suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'reset', 'webscr', 'confirm', 'signin']

def is_phishing_url(url):
    url = url.lower()
    score = 0

    if url.startswith("http://"):
        score += 1
    if re.search(r'\d{1,3}(?:\.\d{1,3}){3}', url):
        score += 1
    if len(url) > 75:
        score += 1
    for keyword in suspicious_keywords:
        if keyword in url:
            score += 1
    if "@" in url or "//" in url[8:]:
        score += 1

    return score >= 2

def extract_urls(email_body):
    return re.findall(r'(https?://[^\s]+)', email_body)

def log_result(email_body, urls, results):
    with open("phishing_scan_log.txt", "a") as f:
        f.write("\n--- Scan at " + str(datetime.datetime.now()) + " ---\n")
        f.write("Email Content:\n" + email_body + "\n\n")
        for i, url in enumerate(urls):
            f.write(f"URL: {url}\nResult: {'Phishing' if results[i] else 'Safe'}\n")
        f.write("\n------------------------\n")

def scan_email():
    email_body = email_input.get("1.0", tk.END)
    urls = extract_urls(email_body)
    results = []

    output_box.delete("1.0", tk.END)

    if not urls:
        output_box.insert(tk.END, "No URLs found in the email.\n")
    else:
        output_box.insert(tk.END, f"Found {len(urls)} URL(s):\n\n")
        for url in urls:
            phishing = is_phishing_url(url)
            results.append(phishing)
            status = "[ALERT] Phishing Detected!" if phishing else "[SAFE] No threats found."
            display_url = "[LINK BLOCKED]" if phishing else url
            output_box.insert(tk.END, f"- {display_url}\n  -> {status}\n\n")
            if phishing:
                messagebox.showwarning("Phishing Detected", f"Phishing link detected:\n{url}\nDo not click this link.")

    log_result(email_body, urls, results)
    messagebox.showinfo("Scan Complete", "Scan complete. Results saved to 'phishing_scan_log.txt'.")

window = tk.Tk()
window.title("Phishing Email Detector - microIT")
window.geometry("800x600")
window.configure(bg="#eaf6f6")

label = tk.Label(window, text="Paste Email Content:", font=("Arial", 14), bg="#eaf6f6")
label.pack(pady=10)

email_input = scrolledtext.ScrolledText(window, width=95, height=12, font=("Arial", 10))
email_input.pack(pady=10)

scan_button = tk.Button(window, text="Scan for Phishing", font=("Arial", 12), bg="#0080ff", fg="white", command=scan_email)
scan_button.pack(pady=5)

result_label = tk.Label(window, text="Scan Results:", font=("Arial", 14), bg="#eaf6f6")
result_label.pack(pady=10)

output_box = scrolledtext.ScrolledText(window, width=95, height=12, font=("Arial", 10))
output_box.pack(pady=10)

tip = tk.Label(window, text="Tip: Never click on links asking you to verify accounts or reset passwords urgently.", font=("Arial", 10), fg="red", bg="#eaf6f6")
tip.pack(pady=5)

window.mainloop()