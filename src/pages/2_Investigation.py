import streamlit as st

from database.connection import Driver
from visualization.dashboard import Dashboard

driver = Driver()
dashboard = Dashboard()


dashboard.display_investigation_dashboards(driver)