import streamlit as st

from database.connection import Driver
from visualization.dashboard import Dashboard

st.set_page_config(layout="wide")

driver = Driver()
dashboard = Dashboard()

findings_by_severity = driver.get_findings_by_severity()
total_unique_findings = driver.get_total_unique_findings()

total_hosts = driver.get_hosts()
total_findings = driver.get_findings()
total_vulnerabilities = driver.get_vulnerabilities()
total_critical_hosts = driver.get_critical_hosts()
country_count = driver.get_country_count()


dashboard.display_general_dashboard(total_hosts, total_critical_hosts, total_findings, total_unique_findings, total_vulnerabilities)
with st.container(border=True):
    col1, col2 = st.columns(2)
    with col1:
        dashboard.display_findings_dashboard(findings_by_severity, total_unique_findings)
    with col2:
        dashboard.display_country_dashboard(country_count)