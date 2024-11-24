import requests

def get_vulnerability_by_cve(cve_code):
    """
    Retrieve vulnerability details from the NIST database using the CVE code.
    
    Args:
        cve_code (str): The CVE code to look up.
    
    Returns:
        dict: A dictionary containing vulnerability details, or None if not found.
    """
    nist_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_code}"
    response = requests.get(nist_url)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Error: {response.status_code}")
        return None
