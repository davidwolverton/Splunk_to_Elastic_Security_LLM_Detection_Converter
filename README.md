# Splunk_to_Elastic_Security_LLM_Detection_Converter
Scripts used to convert Splunk detections to Elastic Security using OpenAI and Google Gemini

Utilized in SANS Master Program research for converting Splunk detections to Elastic Security using LLM's




**Folders**


Python Scripts: Contains the 3 python scripts used to convert and upload the detection content. Documented below
Detection Conversion Files: Contains all the input files and the outputs associated with the 7 tests/conversions ran

**Files:**

SplunkDetectionLogicConverter-Gemini.py 

Purpose: This script iterates over a folder of YAML files and queries Gemini with a pre-defined prompt and the YAML file contents. This script
is used as a part of a SANS Masters research paper determining the effectiveness of LLMs in converting SIEM logic. 

SplunkDetectionLogicConverter-OpenAI.py 

Purpose: This script iterates over a folder of YAML files and queries OpenAI with a pre-defined prompt and the YAML file contents. This script
is used as a part of a SANS Masters research paper determining the effectiveness of LLMs in converting SIEM logic. 

Prerequisites for running conversion scripts: 

API Keys for OpenAI and Google Gemini (Note: Billing is required as these are paid services)
Input folder structure containing the .yml files to convert

_________________________________________________________________________________________________________________________________________

ElasticRuleAPICreateDetection.py

ElasticRuleAPICreateDetection.py script takes JSON files containing API payloads as input. These payloads are intended for the Elasticsearch create rule API. Each JSON file must contain only the payload and no additional data. The script processes all files and organizes the output into two folders: "Completed" and "Failed." An api_error.log file is also generated to record any errors encountered during ingestion.

Elastic Create Detections Script Prerequisites:

API Keys for Elastic Security
Elastic Security Host URL
Input folder containing the .JSON files to upload into Elastic Security
Custom tag to increase filtering ability in Elastic and distinguish between tests
