import configparser
import streamlit as st
from neo4j import GraphDatabase
import pandas as pd
import plotly.express as px

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Read connection details from config file
uri = config['NEO4J']['URI']
user = config['NEO4J']['USER']
password = config['NEO4J']['PASSWORD']

# Initialize Neo4j driver
driver = GraphDatabase.driver(uri, auth=(user, password))

def get_findings_by_severity():
    with driver.session() as session:
        result = session.run(
            """
            MATCH (n:Finding)
            RETURN n.severity AS Severity, COUNT(n) AS Count
            """
        )
        return pd.DataFrame([r.data() for r in result])

def get_total_unique_findings():
    with driver.session() as session:
        result = session.run(
            """
            MATCH (n:Finding)
            RETURN COUNT(DISTINCT n.title) AS UniqueFindingsCount
            """
        )
        return result.single().value()

st.title('Findings Dashboard')

# Load data
findings_by_severity_df = get_findings_by_severity()

# Calculate total unique findings
total_unique_findings = get_total_unique_findings()
# Display total unique findings
st.metric(label="Total Unique Findings", value=total_unique_findings)

# Create pie chart with custom colors
fig = px.pie(
    findings_by_severity_df,
    names='Severity',
    values='Count',
    title='Findings by Severity',
    color='Severity',
    color_discrete_map={
        'Low': 'yellow',
        'Medium': 'orange',
        'High': 'red'
    }
)

# Streamlit app

st.plotly_chart(fig)