import os  # Needed for directory scanning
import hashlib  # To generate file hashes
import requests  # To make API requests to VirusTotal
from cryptography.fernet import Fernet  # For file encryption

print("Script is starting...")

# VirusTotal API key (replace with your own API key)
API_KEY = "INPUT YOUR API KEY HERE"
VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report"

# Generate a key for encryption (use this key securely in production)
# For a real application, you should load this from a secure location
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# Function to generate MD5 hash of a file
def hash_file(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

# Function to scan a file hash using VirusTotal API
def scan_with_virustotal(file_hash):
    params = {"apikey": API_KEY, "resource": file_hash}
    response = requests.get(VIRUSTOTAL_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Unable to connect to VirusTotal API (Status Code: {response.status_code})")
        return None

# Function to analyze the VirusTotal response
def analyze_virustotal_response(response):
    if response:
        response_code = response.get("response_code")
        if response_code == 1:
            positives = response.get("positives", 0)
            total = response.get("total", 0)
            if positives > 0:
                print(f"Malware detected: {positives}/{total} antivirus engines flagged this file.")
                return True
            else:
                print("No malware detected by VirusTotal.")
                return False
        elif response_code == 0:
            print("File not found in VirusTotal database.")
            return False
        else:
            print(f"Unexpected response code: {response_code}")
            return False
    else:
        print("Error: No response from VirusTotal.")
        return False

# Function to move and encrypt infected file to quarantine folder
def quarantine_file(file_path, quarantine_dir):
    if not os.path.exists(quarantine_dir):
        os.makedirs(quarantine_dir)
        
        # Set secure permissions (read/write/execute for owner only)
        os.chmod(quarantine_dir, 0o700)  # Linux-specific; can be ignored on Windows

    try:
        # Encrypt the file
        with open(file_path, "rb") as f:
            file_data = f.read()
        encrypted_data = cipher.encrypt(file_data)

        # Write the encrypted file to the quarantine folder
        encrypted_file_path = os.path.join(quarantine_dir, os.path.basename(file_path) + ".enc")
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Remove the original file
        os.remove(file_path)
        
        print(f"File encrypted and moved to quarantine: {encrypted_file_path}")
    except Exception as e:
        print(f"Error moving file {file_path} to quarantine: {e}")

# Main function to scan a directory
def scan_directory(directory, quarantine_dir):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path)
            if file_hash:
                print(f"\nScanning file: {file_path} (MD5: {file_hash})")
                response = scan_with_virustotal(file_hash)
                if analyze_virustotal_response(response):
                    quarantine_file(file_path, quarantine_dir)

# Main execution block
if __name__ == "__main__":
    directory_to_scan = input("Enter the directory to scan: ")
    quarantine_directory = input("Enter the quarantine directory: ")
    scan_directory(directory_to_scan, quarantine_directory)
