import streamlit as st
from groq import Groq
import configparser
import os
from database.nist import get_vulnerability_by_cve
import json

system_prompt = """
You are an Incident Manager, helping the Teams to find mitigations for Security Incidents. The User provides you with a description of the Vulnerability. You then provide the User with a Mitigation. This can either be an "ansible" playbook to be executed on the vulnerable servers. The other type is "manual", there you just provide a step by step plan for the Teams should do to mitigate the vulnerability formatted in markdown, like "Add a Firewall Rule to the central Firewall, to deny all external traffic to the Kubernetes Master Nodes on their KubeAPI Port". The Description should be a short description of the Mitigation used in both cases.
"content" and "description" values need to be escaped properly into one line!
For Ansible Mitigations, further mitigations can be provided in the description in markdown format.
Ansible Mitigations are preffered, even if they are just partial
You answer in JSON Format Only!!
Example:
{"type": "ansible","content": ""---\n- hosts: all\n  tasks:\n    - name: Print JSON value\n      debug:\n        msg: \"{{ my_json_value.key1 }}\"\n      vars:\n        my_json_value: \'{\"key1\": \"value1\", \"key2\": \"value2\"}\'\n", "description": "This is just an example for an ansible playbook"}
"""

def get_groq_client():
    path = os.path.join(os.path.dirname(__file__), '..', 'config.ini')
    if os.path.exists(path):
        config = configparser.ConfigParser()
        config.read(path)
        api_key = config['GROQ']['API_KEY']
    else:
        api_key = os.getenv('GROQ_API_KEY')

    groq = Groq(api_key=api_key)
    return groq

def get_mitigations(cve_details, retries=3):
    groq = get_groq_client()
    response = groq.chat.completions.create(
        model="llama3-70b-8192",
        messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": cve_details}],
        temperature=0.8
    )
    if response.choices[0].message.content is not None:
        
        try:
            response = json.loads(response.choices[0].message.content)
        except json.JSONDecodeError:
            if retries > 0:
                print(f"JSONDecodeError, retrying... {retries} retries left. Content: {response.choices[0].message.content}")
                return get_mitigations(cve_details, retries - 1)
            else:
                return None
        ## Check that all keys are present and valid types
        if 'type' not in response or 'content' not in response or 'description' not in response:
            if retries > 0:
                print("Invalid JSON, retrying...")
                return get_mitigations(cve_details, retries - 1)
            else:
                return None
        if response['type'] not in ['ansible', 'manual']:
            if retries > 0:
                print("Invalid Mitigation Type, retrying...")
                return get_mitigations(cve_details, retries - 1)
            else:   
                return None
        return response
    else:
        return None
    

def display_mitigations():
    st.title('Mitigations')
    
    # Initialize session state if needed
    if 'cve_details' not in st.session_state:
        st.session_state.cve_details = ''

    cve_id = st.text_input('Enter CVE ID', key='cve_id')

    # Button to get CVE details from NIST
    if st.button('Get CVE Details from NIST'):
        if cve_id:
            cve_details_from_db = get_vulnerability_by_cve(cve_id)
            if cve_details_from_db is not None:
                st.session_state.cve_details = cve_details_from_db
                st.rerun()
            else:
                st.error('CVE not found')
        else:
            st.error('Please enter a CVE ID')

    # Always show the text area for CVE details
    cve_details = st.text_area('CVE Details', value=st.session_state.cve_details, key='cve_details_input')

    if st.button('Get Mitigations from Groq'):
        mitigations = get_mitigations(cve_details)  # Use the current text area value
        if mitigations is not None:
            st.session_state.mitigations = mitigations
            st.rerun()
        else:
            st.error('No mitigations found')

    if 'mitigations' in st.session_state:
        mitigations = st.session_state.mitigations
        if mitigations['type'] == 'ansible':
            st.subheader('Ansible Playbook')
            st.markdown(mitigations['description'])
            st.code(mitigations['content'], language='yaml')
            st.warning("This code is AI generated, please verify it! It can negatively impact the production environment! Just use it as a starting point!")
        else:
            st.subheader('Manual Mitigation')
            st.markdown(mitigations['content'])

display_mitigations()

