import streamlit as st

from database.connection import Driver
from visualization.dashboard import Dashboard

driver = Driver()
dashboard = Dashboard()

findings_by_severity = driver.get_findings_by_severity()
total_unique_findings = driver.get_total_unique_findings()

dashboard.display_dashboard(findings_by_severity, total_unique_findings)