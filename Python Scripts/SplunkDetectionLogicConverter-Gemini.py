import os
import yaml
import google.generativeai as genai
import datetime

"""
Author: David Wolverton
Date: 3/3/2025
Purpose: This script iterates over a folder of YAML files and queries Gemini with a pre defined prompt and the YAML file contents. This script
is used as apart of a SANS Masters research paper determining the effectiveness of LLM's in converting SIEM logic. 

"""


def process_yaml_files(folder_path, prompt_template, api_key, output_folder):
    """
    Reads YAML files from a folder, queries Gemini, and saves each result to an individual JSON file.

    Args:
        folder_path (str): The path to the folder containing YAML files.
        prompt_template (str): The base prompt template for Gemini.
        api_key (str): Your Gemini API key.
    """

    genai.configure(api_key=api_key)
    #Note: Currently using Gemini 2.0 Flash 001 may need to update with latest model/specific model you are testing with
    model = genai.GenerativeModel('gemini-2.0-flash-001')

    for filename in os.listdir(folder_path):
        if filename.endswith(".yml") or filename.endswith(".yaml"):
            file_path = os.path.join(folder_path, filename)

            if not os.path.exists(file_path): # Debug: Check if file exists
                print(f"File not found: {file_path}")
                continue

            try:
                with open(file_path, "r") as file:
                    yaml_data = yaml.safe_load(file)

                
                yaml_content = yaml.dump(yaml_data)
                print(f"YAML Content:\n{yaml_content}")

                full_prompt = f"{prompt_template}{yaml_content}"
                print(full_prompt)
                response = model.generate_content(
                    full_prompt,
                    generation_config=genai.GenerationConfig(
                        temperature=0.8,  # Adjust temperature here
                        )
                    )
                gemini_response = response.text
                
                #Removes the json header and ending to leave only the raw json so another script can read it in directly. 
                if gemini_response.startswith("```json"):
                    gemini_response = gemini_response[7:]
                if gemini_response.endswith("```"):
                    gemini_response = gemini_response[:-3]
                if gemini_response.startswith("'''json"):
                    gemini_response = gemini_response[7:]
                if gemini_response.endswith("'''"):
                    gemini_response = gemini_response[:-3]

                #Remove leading or trailing whitespace
                gemini_response = gemini_response.strip()
             

                rule_name = "Unknown_Rule"
                if isinstance(yaml_data, dict) and "name" in yaml_data:
                    rule_name = yaml_data["name"].replace(" ", "_")

                output_filename = f"{rule_name}.json"
                output_path = os.path.join(output_folder, output_filename)

                with open(output_path, "w") as output:
                    output.write(gemini_response)

                print(f"Output written to {output_path}")

            except FileNotFoundError:
                print(f"File not found: {file_path}")
            except yaml.YAMLError as e:
                print(f"Error parsing YAML file {file_path}: {e}")
            except Exception as e:
                print(f"An error occurred processing {file_path}: {e}")

def main():
    """
    Main function to execute the script.
    """
    folder_path = r"""Placeholder\File\Path"""  
    prompt_template="You are an expert in log analysis and query conversion, specializing in Splunk and the Elastic ELK Security stack. Your task is to convert a given splunk SPL Query into an equivalent Elastic ELK query ensuring that the same functionality and logic remain. Your guidelines are to maintain all filtering logic including equivalent names, conditions and operations to match Elastic Query DSL syntax. When translating fields when possible align to the Elastic Common Schema for field names where appropriate. Translate all functions from SPL including eval stats search rex lookups to their equivalent ELK counterparts. Use KQL or Query DSL however prefer Kibana query language where possible but you may use Elastic search query DSL for complex queries. Be mindful that splunks fields may differ from elastic search fields mapping and adjust accordingly. Have a security focus as all of these searches relate to SIEM use cases such as threat detection and log correlation. Ensure that the conversion aligns with elastic security features. Align the output to that of an API Post to the /api/detection/engine/rules endpoint of the elastic security api. Reference documentation and link can be found here: https://www.elastic.co/docs/api/doc/kibana/v8/operation/operation-createrule Provide the output as only the json payload to the api post and no further explanation or context given to the conversion unless you anticipate an error in the conversion. Prepend the rule name with Google Gemini 2.0 Flash 001 and also add a note into the description that the rule was converted with Google Gemini 2.0 Flash 001 as well as adding that as an author and tag. Be extra mindful of the Elastic Security API's required JSON structure, specifically for the threat object. The threat object requires the following structure: tactics is an object containing id and name keys and technique is an array of objects each containing id and name keys. Ensure the output is configured in a json format and has no errors in the json formatting/parsing. When converting Splunk SPL to Elastic ELK queries, adhere strictly to the Elastic Security API's JSON structure. Avoid providing string values directly for 'tactic' or 'technique' and always include the 'reference' key in the 'technique' objects. Remember the correct JSON structure for the 'threat' object and avoid generating errors related to data types or missing required fields. Ensure the 'language'' field within the 'rule' object is set to 'eql'. Do not use 'kuery' Please reference this as a sample of the api structure {'actions': [{'action_type_id': 'string', 'alerts_filter': {}, 'frequency': {'notifyWhen': 'onActiveAlert', 'summary': True, 'throttle': 'no_actions'}, 'group': 'string', 'id': 'string', 'params': {}, 'uuid': 'string'}], 'alias_purpose': 'savedObjectConversion', 'alias_target_id': 'string', 'author': ['string'], 'building_block_type': 'string', 'description': 'string', 'enabled': True, 'exceptions_list': [{'id': 'string', 'list_id': 'string', 'namespace_type': 'agnostic', 'type': 'detection'}], 'false_positives': ['string'], 'from': 'string', 'interval': 'string', 'investigation_fields': {'field_names': ['string']}, 'license': 'string', 'max_signals': 42, 'meta': {}, 'name': 'string', 'namespace': 'string', 'note': 'string', 'outcome': 'exactMatch', 'output_index': 'string', 'references': ['string'], 'related_integrations': [{'integration': 'string', 'package': 'string', 'version': 'string'}], 'required_fields': [{'name': 'string', 'type': 'string'}], 'response_actions': [{'action_type_id': '.osquery', 'params': {'ecs_mapping': {'additionalProperty1': {'field': 'string', 'value': 'string'}, 'additionalProperty2': {'field': 'string', 'value': 'string'}}, 'pack_id': 'string', 'queries': [{'ecs_mapping': {'additionalProperty1': {'field': 'string', 'value': 'string'}, 'additionalProperty2': {'field': 'string', 'value': 'string'}}, 'id': 'string', 'platform': 'string', 'query': 'string', 'removed': True, 'snapshot': True, 'version': 'string'}], 'query': 'string', 'saved_query_id': 'string', 'timeout': 42.0}}], 'risk_score': 42, 'risk_score_mapping': [{'field': 'string', 'operator': 'equals', 'risk_score': 42, 'value': 'string'}], 'rule_id': 'string', 'rule_name_override': 'string', 'setup': 'string', 'severity': 'low', 'severity_mapping': [{'field': 'string', 'operator': 'equals', 'severity': 'low', 'value': 'string'}], 'tags': ['string'], 'threat': [{'framework': 'string', 'tactic': {'id': 'string', 'name': 'string', 'reference': 'string'}, 'technique': [{'id': 'string', 'name': 'string', 'reference': 'string', 'subtechnique': [{'id': 'string', 'name': 'string', 'reference': 'string'}]}]}], 'throttle': 'no_actions', 'timeline_id': 'string', 'timeline_title': 'string', 'timestamp_override': 'string', 'timestamp_override_fallback_disabled': True, 'to': 'string', 'version': 42, 'language': 'eql', 'query': 'string', 'type': 'eql', 'alert_suppression': {'duration': {'unit': 's', 'value': 42}, 'group_by': ['string'], 'missing_fields_strategy': 'doNotSuppress'}, 'data_view_id': 'string', 'event_category_override': 'string', 'filters': [], 'index': ['string'], 'tiebreaker_field': 'string', 'timestamp_field': 'string'}"
    api_key = "Placeholder-api-key"
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_folder = os.path.join(folder_path, f"Gemini_Converted_Outputs_{timestamp}")
    os.makedirs(output_folder, exist_ok=True)

    process_yaml_files(folder_path, prompt_template, api_key, output_folder)
    print("Processing complete. JSON outputs saved for each rule.")

if __name__ == "__main__":
    main()
