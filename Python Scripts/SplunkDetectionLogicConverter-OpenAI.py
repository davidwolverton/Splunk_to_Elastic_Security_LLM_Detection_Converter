import openai
import os
import yaml
import datetime
from openai import OpenAI

# Function to fix problematic bytes by replacing them with '?'
def fix_problematic_bytes(byte_string):
    fixed_string = ""
    for byte in byte_string:
        try:
            # Try to decode each byte as UTF-8, otherwise replace with '?'
            fixed_string += byte.to_bytes(1, 'big').decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            # Replace any problematic byte with '?'
            fixed_string += '?'
    return fixed_string

#Pre defined prompt input
promptinput="You are an expert in log analysis and query conversion, specializing in Splunk and the Elastic ELK Security stack. Your task is to convert a given splunk SPL Query into an equivalent Elastic ELK query ensuring that the same functionality and logic remain. Your guidelines are to maintain all filtering logic including equivalent names, conditions and operations to match Elastic Query DSL syntax. When translating fields when possible align to the Elastic Common Schema for field names where appropriate. Translate all functions from SPL including eval stats search rex lookups to their equivalent ELK counterparts. Use KQL or Query DSL however prefer Kibana query language where possible but you may use Elastic search query DSL for complex queries. Be mindful that splunks fields may differ from elastic search fields mapping and adjust accordingly. Have a security focus as all of these searches relate to SIEM use cases such as threat detection and log correlation. Ensure that the conversion aligns with elastic security features. Align the output to that of an API Post to the /api/detection/engine/rules endpoint of the elastic security api. Reference documentation and link can be found here: https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-createrule Provide the output as only the json payload to the api post and no further explanation or context given to the conversion unless you anticipate an error in the conversion. Prepend the rule name with OpenAI GPT4-o and also add a note into the description that the rule was converted with OpenAI GPT4-o as well as adding that as an author and tag. Be extra mindful of the Elastic Security API's required JSON structure, specifically for the threat object. The threat object requires the following structure: tactics is an object containing id and name keys and technique is an array of objects each containing id and name keys. Ensure the output is configured in a json format and has no errors in the json formatting/parsing. When converting Splunk SPL to Elastic ELK queries, adhere strictly to the Elastic Security API's JSON structure. Avoid providing string values directly for 'tactic' or 'technique' and always include the 'reference' key in the 'technique' objects. Remember the correct JSON structure for the 'threat' object and avoid generating errors related to data types or missing required fields. Ensure the 'language'' field within the 'rule' object is set to 'eql'. Do not use 'kuery' Please reference this as a sample of the api structure {'actions': [{'action_type_id': 'string', 'alerts_filter': {}, 'frequency': {'notifyWhen': 'onActiveAlert', 'summary': True, 'throttle': 'no_actions'}, 'group': 'string', 'id': 'string', 'params': {}, 'uuid': 'string'}], 'alias_purpose': 'savedObjectConversion', 'alias_target_id': 'string', 'author': ['string'], 'building_block_type': 'string', 'description': 'string', 'enabled': True, 'exceptions_list': [{'id': 'string', 'list_id': 'string', 'namespace_type': 'agnostic', 'type': 'detection'}], 'false_positives': ['string'], 'from': 'string', 'interval': 'string', 'investigation_fields': {'field_names': ['string']}, 'license': 'string', 'max_signals': 42, 'meta': {}, 'name': 'string', 'namespace': 'string', 'note': 'string', 'outcome': 'exactMatch', 'output_index': 'string', 'references': ['string'], 'related_integrations': [{'integration': 'string', 'package': 'string', 'version': 'string'}], 'required_fields': [{'name': 'string', 'type': 'string'}], 'response_actions': [{'action_type_id': '.osquery', 'params': {'ecs_mapping': {'additionalProperty1': {'field': 'string', 'value': 'string'}, 'additionalProperty2': {'field': 'string', 'value': 'string'}}, 'pack_id': 'string', 'queries': [{'ecs_mapping': {'additionalProperty1': {'field': 'string', 'value': 'string'}, 'additionalProperty2': {'field': 'string', 'value': 'string'}}, 'id': 'string', 'platform': 'string', 'query': 'string', 'removed': True, 'snapshot': True, 'version': 'string'}], 'query': 'string', 'saved_query_id': 'string', 'timeout': 42.0}}], 'risk_score': 42, 'risk_score_mapping': [{'field': 'string', 'operator': 'equals', 'risk_score': 42, 'value': 'string'}], 'rule_id': 'string', 'rule_name_override': 'string', 'setup': 'string', 'severity': 'low', 'severity_mapping': [{'field': 'string', 'operator': 'equals', 'severity': 'low', 'value': 'string'}], 'tags': ['string'], 'threat': [{'framework': 'string', 'tactic': {'id': 'string', 'name': 'string', 'reference': 'string'}, 'technique': [{'id': 'string', 'name': 'string', 'reference': 'string', 'subtechnique': [{'id': 'string', 'name': 'string', 'reference': 'string'}]}]}], 'throttle': 'no_actions', 'timeline_id': 'string', 'timeline_title': 'string', 'timestamp_override': 'string', 'timestamp_override_fallback_disabled': True, 'to': 'string', 'version': 42, 'language': 'eql', 'query': 'string', 'type': 'eql', 'alert_suppression': {'duration': {'unit': 's', 'value': 42}, 'group_by': ['string'], 'missing_fields_strategy': 'doNotSuppress'}, 'data_view_id': 'string', 'event_category_override': 'string', 'filters': [], 'index': ['string'], 'tiebreaker_field': 'string', 'timestamp_field': 'string'}"


# Function to read the contents of a .yml file
# Iterate over all provided .yml files (Splunk Detections to convert)
def read_yml_file(file_path):
    try:
        with open(file_path, 'r') as file:
            print("Reading the file")
            return yaml.safe_load(file)  # Parse the YAML contents
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

# Initialize OpenAI

client = OpenAI(api_key="placeholder")

# Function to send the prompt to OpenAI using the new API
def get_chatgpt_response(prompt, filename, output_folder):
    try:
        # Send the prompt to the OpenAI API using the new method for chat completions
        completion = client.chat.completions.create(
            model="gpt-4o",  # Ensure the model name is correct, or change it to another model if needed
            temperature=0.6,  # Add the temperature parameter here
            messages=[
                {"role": "system", "content": "You are an expert in log analysis and query conversion, specializing in Splunk and the Elastic ELK Security Stack."},
                {"role": "user", "content": prompt}
            ]
        )

        # Print the full response to the terminal for debugging
        print("Full response from OpenAI API:")
        print(completion)

        # Get the response text from the first choice
        response_text = completion.choices[0].message.content.strip()

        #Remove json file headers
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        if response_text.startswith("'''json"):
            response_text = response_text[7:]
        if response_text.endswith("'''"):
            response_text = response_text[:-3]

        #stripping all leading or trailing whitepsace
        response_text = response_text.strip()

        # Save the response to a text file
        output_filename = f"{filename}-output.json"
        output_path = os.path.join(output_folder, output_filename)


        with open(output_path, 'w') as file:
            file.write(response_text)

        print(f"Response for {filename} saved as {output_path}")

    except Exception as e:
        print(f"Error occurred while processing {filename}: {e}")

# Function to iterate through all .yml files in a given folder
def process_yml_files(folder_path, output_folder):
    # Ensure the folder exists
    if not os.path.isdir(folder_path):
        print(f"Invalid folder path: {folder_path}")
        return

    # Iterate through all files in the folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".yml"):
            file_path = os.path.join(folder_path, filename)

            # Read the content of the .yml file
            yml_content = read_yml_file(file_path)
            if yml_content:
                # Create the prompt by appending .yml content to the predefined prompt
                prompt = f"{promptinput}\n{str(yml_content)}"
                print(prompt)

                # Send the prompt to ChatGPT and save the response
                get_chatgpt_response(prompt, filename, output_folder)

# Main execution
if __name__ == "__main__":

    #Input folder path
    folder_path = r'\Placeholder\File\Path'

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    output_folder = os.path.join(folder_path, f"ChatGPT-4o_Converted_Outputs_{timestamp}")
    os.makedirs(output_folder, exist_ok=True)

    process_yml_files(folder_path, output_folder)

    print("All files processed.")
