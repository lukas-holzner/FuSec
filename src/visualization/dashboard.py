import streamlit as st
import plotly.express as px
import re


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

        st.plotly_chart(fig)

    def display_investigation_dashboards(self, driver):
        if 'button_state' not in st.session_state:
            st.session_state.button_state = False

        if 'load_data' not in st.session_state:
            st.session_state.load_data = False

        host_criticality_count_df = None
        host_criticality_df = None

        if not st.session_state.load_data:
            host_criticality_count_df = driver.get_host_criticality_count()
            host_criticality_df = driver.get_host_criticality()
            st.session_state.load_data = True


        st.title('Investigation Dashboard')

        search_cve = st.text_input('Search', label_visibility='collapsed', placeholder='🔍 Search CVE')

        if st.button('Advanced search'):
            st.session_state.button_state = not st.session_state.button_state
            st.session_state.load_data = False


        if st.session_state.button_state:
            st.session_state.load_data = True
            # Display advanced search options
            st.subheader('Advanced search options')
            if 'step' not in st.session_state:
                st.session_state.step = 0
                st.session_state.selections = []

                # Step 1: Select Publisher
            if st.session_state.step == 0:
                publishers = driver.get_publishers()
                selected_publisher = st.selectbox("Select Publisher", [''] + publishers)

                if selected_publisher:
                    st.session_state.selections.append(selected_publisher)
                    st.session_state.step = 1
                    st.rerun()

                # Step 2: Select Product based on Publisher
            elif st.session_state.step == 1:
                selected_publisher = st.session_state.selections[-1]
                products = driver.get_products(selected_publisher)
                selected_product = st.selectbox("Select Product", [''] + products)

                if selected_product:
                    st.session_state.selections.append(selected_product)
                    st.session_state.step = 2
                    st.rerun()

                # Step 3: Select Version based on Product
            elif st.session_state.step == 2:
                selected_publisher, selected_product = st.session_state.selections[-2:]
                versions = driver.get_versions(selected_publisher, selected_product)
                selected_version = st.selectbox("Select Version", [''] + versions)

                if selected_version:
                    st.session_state.selections.append(selected_version)
                    st.session_state.step = 3

            if st.session_state.step == 3:
                st.session_state.step = 0
                st.rerun()

                # Execute the search when all selections are made and a button is pressed
            if st.button("Execute Search"):
                # Create list of publishers, products, and versions from selections
                publishers = []
                products = []
                versions = []

                for i in range(0, len(st.session_state.selections), 3):
                    publishers.append(st.session_state.selections[i])
                    products.append(st.session_state.selections[i + 1] if i + 1 < len(st.session_state.selections) else None)
                    versions.append(st.session_state.selections[i + 2] if i + 2 < len(st.session_state.selections) else None)

                table = driver.advanced_search(publishers, products, versions)
                st.table(table)
        else:

            if re.match(r'^CVE-\d{4}-\d{4,}$', search_cve):
                st.write(f'Showing results for {search_cve}')
            elif search_cve != '🔍 Search CVE':
                # Search for everything

                if host_criticality_count_df is None or host_criticality_df is None:
                    host_criticality_count_df = driver.get_host_criticality_count()
                    host_criticality_df = driver.get_host_criticality()
                    st.session_state.load_data = True
                # Add a checkbox to include/exclude 'N/A' values
                include_na = st.checkbox('Include N/A', value=False)

                if not include_na:
                    host_criticality_count_df = host_criticality_count_df[host_criticality_count_df['risk_level'] != 'N/A']
                    host_criticality_df = host_criticality_df[host_criticality_df['risk_level'] != 'N/A']

                fig = px.pie(
                    host_criticality_count_df,
                    names='risk_level',
                    values='count',
                    title='Host Criticality',
                    color='risk_level',
                    color_discrete_map={
                        'N/A': 'green',
                        'Low': 'yellow',
                        'Medium': 'orange',
                        'High': 'red',
                        'Critical': 'darkred'
                    }
                )

                st.plotly_chart(fig)

                st.subheader('Top 10 Hosts by Criticality')

                host_criticality_df = host_criticality_df.head(10)
                st.table(host_criticality_df)
