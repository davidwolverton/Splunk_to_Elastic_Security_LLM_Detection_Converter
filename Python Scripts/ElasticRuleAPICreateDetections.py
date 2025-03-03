import requests
import json
import os
import shutil
import logging

# Define local variables
ELASTIC_HOST = "https://placeholder/elastic.cloud"  # Replace with your Kibana URL
ELASTIC_API_KEY = "placholder"  # Replace with your API Key
API_ENDPOINT = f"{ELASTIC_HOST}/api/detection_engine/rules"

# Define modifications
string_to_prepend = "Gemini Test 1 Temp 0.8 "  # Change this to your desired prefix for rule_id (To avoid rule_ID conflicts if rules were converted using various LLM prompt settings)
new_tag_to_add = "Gemini Test 1 Temp 0.8"  # Change this to the tag you want to add (Useful for filtering in Elastic Security)

# Set up logging to output all errors to api_error.log
def setup_logging(failed_dir):
    log_file = os.path.join(failed_dir, "api_errors.log")
    logging.basicConfig(filename=log_file,
                        level=logging.ERROR,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    print(f"Logging errors to {log_file}")

# Load JSON and modify before sending
def load_and_modify_json(file_path):
    print(f"Attempting to load and modify JSON file from: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        
        # Modify rule_id based on the name field
        if "name" in data and "rule_id" in data:
            data["rule_id"] = string_to_prepend + data["name"]

        # Ensure "tags" exists and add new tag if it’s not present
        if "tags" in data and isinstance(data["tags"], list):
            if new_tag_to_add not in data["tags"]:
                data["tags"].append(new_tag_to_add)
        else:
            data["tags"] = [new_tag_to_add]

        print("JSON file modified successfully.")
        return data

    except FileNotFoundError:
        print(f"Error: JSON file '{file_path}' not found.")
        logging.error(f"FileNotFoundError: JSON file '{file_path}' not found.")
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON file '{file_path}'. Ensure it is correctly formatted.")
        logging.error(f"JSONDecodeError: Failed to parse JSON file '{file_path}'. Ensure it is correctly formatted.")
    except Exception as e:
        print(f"An unexpected error occurred while loading the JSON file: {e}")
        logging.error(f"Unexpected error while loading JSON file {file_path}: {e}")

    return None

# Create a rule in Elastic Security
def create_elastic_rule(rule_data, filename, failed_dir):
    print(f"Creating rule for {filename}...")
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {ELASTIC_API_KEY}"
    }

    try:
        response = requests.post(API_ENDPOINT, headers=headers, data=json.dumps(rule_data))
        response.raise_for_status()  # Raise HTTPError for bad responses

        if response.status_code == 200:
            print(f"Rule created successfully for {filename}!")
            return True
        else:
            print(f"Unexpected status code: {response.status_code}")
            logging.error(f"Unexpected status code: {response.status_code} - {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        print(f"Error creating rule: {e}")
        logging.error(f"RequestException: Error creating rule: {e}")
        return False

# API Connectivity Test
def test_api_connectivity():
    print("Testing API connectivity...")
    try:
        response = requests.get(ELASTIC_HOST, timeout=5)
        response.raise_for_status()
        print("API connectivity test successful.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"API connectivity test failed: {e}")
        logging.error(f"API connectivity test failed: {e}")
        return False

# Create required directories
def create_directories(base_dir):
    completed_dir = os.path.join(base_dir, "Completed")
    failed_dir = os.path.join(base_dir, "Failed")

    os.makedirs(completed_dir, exist_ok=True)
    os.makedirs(failed_dir, exist_ok=True)

    return completed_dir, failed_dir

# Main function
def main(directory_path):
    print("Starting script...")

    if not test_api_connectivity():
        return

    completed_dir, failed_dir = create_directories(directory_path)
    setup_logging(failed_dir)

    try:
        json_files = [f for f in os.listdir(directory_path) if f.endswith('.json')]
    except FileNotFoundError:
        print(f"Error: Directory '{directory_path}' not found.")
        logging.error(f"FileNotFoundError: Directory '{directory_path}' not found.")
        return

    if not json_files:
        print(f"No JSON files found in directory: {directory_path}")
        logging.warning(f"No JSON files found in directory: {directory_path}")
        return

    for filename in json_files:
        file_path = os.path.join(directory_path, filename)
        print(f"Processing file: {filename}")

        rule_data = load_and_modify_json(file_path)
        if not rule_data:
            print(f"Skipping {filename} due to errors.")
            shutil.move(file_path, os.path.join(failed_dir, filename))
            continue

        if create_elastic_rule(rule_data, filename, failed_dir):
            shutil.move(file_path, os.path.join(completed_dir, filename))
            print(f"Moved {filename} to Completed folder.")
        else:
            shutil.move(file_path, os.path.join(failed_dir, filename))
            print(f"Moved {filename} to Failed folder.")

    print("Script execution finished.")

# Ensures script runs only if executed directly
if __name__ == "__main__":
    directory_path = r"C:\Placeholder\"  # Replace with your directory path
    main(directory_path)
    print("Script finished.")
