import re
import os
import datetime
import hashlib

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
    if "@" in url or "//" in url[8:]:
        score += 1
    for keyword in suspicious_keywords:
        if keyword in url:
            score += 1

    return score >= 2

def extract_urls(email_body):
    return re.findall(r'(https?://[^\s]+)', email_body)

def phishing_detector():
    print("=== Phishing Email Detector ===")
    email_body = input("Paste the email content:\n")
    urls = extract_urls(email_body)

    if not urls:
        print("No URLs found in the email.")
        return

    for url in urls:
        result = is_phishing_url(url)
        status = "[ALERT] Phishing Detected!" if result else "[SAFE]"
        print(f"{url} -> {status}")


def scan_files(folder_path):
    print(f"\n=== File Metadata Scan in: {folder_path} ===\n")
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            filepath = os.path.join(root, file)
            stats = os.stat(filepath)
            created = datetime.datetime.fromtimestamp(stats.st_ctime)
            modified = datetime.datetime.fromtimestamp(stats.st_mtime)
            size = stats.st_size

            print(f"File: {file}")
            print(f" Path: {filepath}")
            print(f" Size: {size} bytes")
            print(f" Created: {created}")
            print(f" Modified: {modified}\n")


def get_file_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            return hashlib.sha256(file_data).hexdigest()
    except Exception as e:
        return f"Error: {e}"

def file_hashing_demo():
    file_path = input("Enter path of file to hash: ")
    hash_value = get_file_hash(file_path)
    print(f"SHA-256 Hash: {hash_value}")

def main():
    while True:
        print("\n=== Cybersecurity & Digital Forensics Tool ===")
        print("1. Phishing Email Detector")
        print("2. File Metadata Extractor")
        print("3. File Hashing Tool")
        print("4. Exit")

        choice = input("Choose an option (1-4): ")

        if choice == '1':
            phishing_detector()
        elif choice == '2':
            folder = input("Enter folder path to scan files: ")
            scan_files(folder)
        elif choice == '3':
            file_hashing_demo()
        elif choice == '4':
            print("Exiting... Stay Safe!")
            break
        else:
            print("Invalid choice! Please enter 1, 2, 3 or 4.")

if __name__ == "__main__":
    main()
    