import streamlit as st
import plotly.express as px


class Dashboard:
    def display_general_dashboard(self, total_unique_hosts, total_critical_hosts, total_findings, total_unique_findings, total_vulnerabilities):
        st.title('General Dashboard')

        with st.container(border=True):
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                # Display total unique hosts
                st.metric(label="Total Unique Hosts", value=total_unique_hosts)
            with col2:
                # Display total critical hosts
                st.metric(label="Total Critical Hosts", value=total_critical_hosts)
            with col3:
                # Display total findings
                st.metric(label="Total Findings", value=total_findings)
            with col4:
                # Display unique findings
                st.metric(label="Total Unique Findings", value=total_unique_findings)
            with col5:
                # Display total vulnerabilities
                st.metric(label="Total Vulnerabilities", value=total_vulnerabilities)

    def display_findings_dashboard(self, findings_by_severity_df, total_unique_findings):
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