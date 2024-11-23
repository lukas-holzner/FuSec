import streamlit as st
import plotly.express as px

class Dashboard:
    def display_dashboard(self, findings_by_severity_df, total_unique_findings):
        st.title('Findings Dashboard')

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