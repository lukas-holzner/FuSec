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

    def display_country_dashboard(self, country_count_df):
        st.title('Country Dashboard')

        fig = px.choropleth(
            country_count_df,
            locations="country",
            locationmode="country names",
            color="count",
            color_continuous_scale="Viridis",
            title="Occurrences by Country",
        )

        st.plotly_chart(fig)

    def display_investigation_dashboards(self, driver):
        if 'button_state' not in st.session_state:
            st.session_state.button_state = False

        if 'load_data' not in st.session_state:
            st.session_state.load_data = False

        if 'selections' not in st.session_state:
            st.session_state.selections = []

        if 'selection_steps' not in st.session_state:
            st.session_state.selection_steps = []

        if 'sequences' not in st.session_state:
            st.session_state.sequences = [{}]  # Start with one empty sequence

        st.title('Investigation Dashboard')

        search_cve = st.text_input('Search', label_visibility='collapsed', placeholder='🔍 Search CVE')

        if st.button('Advanced search'):
            st.session_state.advanced_search_active = not st.session_state.get('advanced_search_active', False)

        if st.session_state.get('advanced_search_active', False):
            st.subheader('Advanced Search Options')

            # Add and remove sequences
            col1, col2, col3 = st.columns([1, 1, 1])
            with col1:
                if st.button('➕ Add Sequence'):
                    st.session_state.sequences.append({})
            with col2:
                if st.button('➖ Remove Last Sequence') and len(st.session_state.sequences) > 1:
                    st.session_state.sequences.pop()
            with col3:
                if st.button('🔄 Reset Sequences'):
                    st.session_state.sequences = [{}]

            # Iterate through sequences and dynamically build selection boxes
            for idx, sequence in enumerate(st.session_state.sequences):
                st.markdown(f"**Sequence {idx + 1}**")

                # Select Publisher
                publishers = driver.get_publishers()
                selected_publisher = st.selectbox(
                    f"Publisher for Sequence {idx + 1}",
                    options=[''] + publishers,
                    index=publishers.index(sequence.get('publisher', '')) + 1 if 'publisher' in sequence else 0,
                    key=f"publisher_{idx}",
                )
                if selected_publisher:
                    st.session_state.sequences[idx]['publisher'] = selected_publisher

                    # Select Product
                    products = driver.get_products(selected_publisher)
                    selected_product = st.selectbox(
                        f"Product for Sequence {idx + 1}",
                        options=[''] + products,
                        index=products.index(sequence.get('product', '')) + 1 if 'product' in sequence else 0,
                        key=f"product_{idx}",
                    )
                    if selected_product:
                        st.session_state.sequences[idx]['product'] = selected_product

                        # Select Version Range
                        versions = driver.get_versions(selected_publisher, selected_product)
                        selected_min_version = st.selectbox(
                            f"Minimum Version for Sequence {idx + 1}",
                            options=[''] + versions,
                            index=versions.index(
                                sequence.get('min_version', '')) + 1 if 'min_version' in sequence else 0,
                            key=f"min_version_{idx}",
                        )
                        if selected_min_version:
                            st.session_state.sequences[idx]['min_version'] = selected_min_version
                            # Remove versions that are less than the selected min version
                            versions = [version for version in versions if version >= selected_min_version]

                        selected_max_version = st.selectbox(
                            f"Maximum Version for Sequence {idx + 1}",
                            options=[''] + versions,
                            index=versions.index(
                                sequence.get('max_version', '')) + 1 if 'max_version' in sequence else 0,
                            key=f"max_version_{idx}",
                        )
                        if selected_max_version:
                            st.session_state.sequences[idx]['max_version'] = selected_max_version

            include_na_filtered = st.checkbox('Include N/A', value=False)
            # Execute the search when ready
            if st.button('Execute Search'):
                # Collect data for search
                publishers = [seq.get('publisher') for seq in st.session_state.sequences if 'publisher' in seq]
                products = [seq.get('product') for seq in st.session_state.sequences if 'product' in seq]
                min_versions = [seq.get('min_version') for seq in st.session_state.sequences if 'min_version' in seq]
                max_versions = [seq.get('max_version') for seq in st.session_state.sequences if 'max_version' in seq]

                table, pie_df = driver.advanced_search(publishers, products, min_versions, max_versions)
                if not include_na_filtered:
                    pie_df = pie_df[pie_df['risk_level'] != 'N/A']
                    table = table[table['risk_level'] != 'N/A']
                fig = px.pie(
                    pie_df,
                    names='risk_level',
                    values='count',
                    title='Host Criticality',
                    color='risk_level',
                    color_discrete_map={
                        'N/A': 'green',
                        'Low': 'yellow',
                        'Medium': 'orange',
                        'High': 'red',
                        'Critical': 'darkred',
                    },
                )
                st.plotly_chart(fig)
                st.table(table)


        else:
            if re.match(r'^CVE-\d{4}-\d{4,}$', search_cve):
                st.write(f'Showing results for {search_cve}')
            elif search_cve != '🔍 Search CVE':
                # Handle non-specific search
                host_criticality_count_df = driver.get_host_criticality_count()
                host_criticality_df = driver.get_host_criticality()

                include_na = st.checkbox('Include N/A', value=False)
                if not include_na:
                    host_criticality_count_df = host_criticality_count_df[
                        host_criticality_count_df['risk_level'] != 'N/A'
                        ]
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
                        'Critical': 'darkred',
                    },
                )
                st.plotly_chart(fig)

                st.subheader('Top 10 Hosts by Criticality')
                host_criticality_df = host_criticality_df.head(10)
                st.table(host_criticality_df)
