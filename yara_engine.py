import yara
import os
import sys
import requests
import base64
import logging

#Author: Cooper

API_KEY = 'x'
scan_url = "https://www.virustotal.com/api/v3/files"

# Compile YARA rules
compiled_rules = yara.compile('yara_engine.yar')

logging.basicConfig(level=logging.ERROR)  # Set logging level to ERROR

def decode_base64(line):
    # Check if the line contains valid base64 characters
    if all(c in base64.b64encode(line.strip().encode()) for c in line.strip().encode()):
        try:
            # Decode the base64 encoded line
            decoded_line = base64.b64decode(line.strip()).decode('utf-8')
            return decoded_line
        except (UnicodeDecodeError, binascii.Error) as e:
            print("Unable to decode line with UTF-8 encoding:", line)
            print("Error:", e)
            return None
    else:
        # Return the line as is if it does not contain valid base64 characters
        return line.strip()


def upload_file(file_path):
    try:
        with open(file_path, "rb") as file:
            files = {"file": (file.name, file, "application/octet-stream")}
            scan_headers = {"x-apikey": API_KEY}

            # Upload file to VirusTotal
            response = requests.post(scan_url, files=files, headers=scan_headers)
            response.raise_for_status()  # Raise an exception for HTTP errors

            return response.json()
    except (FileNotFoundError, requests.exceptions.RequestException) as e:
        logging.error(f"Error occurred while uploading file: {e}")
        return None


def get_analysis_results(analysis_id):
    try:
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_headers = {"x-apikey": API_KEY}

        # Retrieve analysis results
        response = requests.get(analysis_url, headers=analysis_headers)
        response.raise_for_status()  # Raise an exception for HTTP errors

        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error occurred while fetching analysis results: {e}")
        return None


def process_file(file_path):
    try:
        analysis_data = upload_file(file_path)
        if analysis_data:
            analysis_id = analysis_data.get("data", {}).get("id")
            if analysis_id:
                results = get_analysis_results(analysis_id)
                if results:
                    attributes = results.get("data", {}).get("attributes", {})
                    stats = attributes.get("stats", {})
                    print(f"Scan results for file: {file_path}")
                    print("Detection summary:")
                    print(f"Malicious: {stats.get('malicious', 0)}")
                    print(f"Suspicious: {stats.get('suspicious', 0)}")
                    print(f"Undetected: {stats.get('undetected', 0)}")
                    print(f"Harmless: {stats.get('harmless', 0)}")
                    print(f"Timeout: {stats.get('timeout', 0)}")
                    print(f"Confirmed Timeout: {stats.get('confirmed-timeout', 0)}")
                    print(f"Failure: {stats.get('failure', 0)}")
                    print(f"Type Unsupported: {stats.get('type-unsupported', 0)}")
                    print(f"File Name: {attributes.get('name', '')}")
                    print(f"File Size: {attributes.get('size', '')} bytes")
                    print(f"File Type: {attributes.get('type', '')}")
                    print(f"Upload Time: {attributes.get('creation_date', '')}")
                    print(f"Analysis Time: {attributes.get('last_analysis_date', '')}")
                    print(f"Engines Used: {attributes.get('total_engines', 0)}")
                    print(f"Engines Detected: {attributes.get('total_detected', 0)}")
                    print(f"Community Votes - Malicious: {attributes.get('community_reputation', {}).get('malicious', 0)}")
                    print(f"Community Votes - Harmless: {attributes.get('community_reputation', {}).get('harmless', 0)}")
                    print(f"Comments: {attributes.get('comments', '')}")
                    print("\n")
                    
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def scan_directory(directory):
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path):
        
            if filename.startswith("."):
                print("Hidden file found:", file_path)
                print("\n")
            
            if filename.endswith(".exe"):
                print("Executable file found:", file_path)
                print("\n")
                
            with open(file_path, 'r') as file:
                file_content = file.readlines()

            for line in file_content:
                decoded_line = decode_base64(line)
                matches = compiled_rules.match(data=decoded_line)

                if matches:
                    print("Match found in file:", filename)
                    print("Matched string:", decoded_line)
                    print("\n")
            process_file(file_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 virustotal_api.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    scan_directory(directory)