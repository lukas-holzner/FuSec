import streamlit as st

from database.connection import Driver
from visualization.dashboard import Dashboard

driver = Driver()
dashboard = Dashboard()

findings_by_severity = driver.get_findings_by_severity()
total_unique_findings = driver.get_total_unique_findings()

total_hosts = driver.get_hosts()
total_findings = driver.get_findings()
total_vulnerabilities = driver.get_vulnerabilities()
total_critical_hosts = driver.get_critical_hosts()

dashboard.display_general_dashboard(total_hosts, total_critical_hosts, total_findings, total_unique_findings, total_vulnerabilities)
dashboard.display_findings_dashboard(findings_by_severity, total_unique_findings)