from neo4j import GraphDatabase
import configparser
import os
import pandas as pd


class Driver:
    def __init__(self):
        self.driver = None
        self._load_config()


    def _load_config(self):
        # Determine absolute path to config.ini
        config_path = os.path.join(os.path.dirname(__file__), '..', 'config.ini')

        if os.path.exists(config_path):
            # Load configuration
            config = configparser.ConfigParser()
            config.read(config_path)

            # Read connection details from config file
            uri = config['NEO4J']['URI']
            user = config['NEO4J']['USER']
            password = config['NEO4J']['PASSWORD']
        else:
            # Read connection details from environment variables
            uri = os.getenv('NEO4J_URI')
            user = os.getenv('NEO4J_USER')
            password = os.getenv('NEO4J_PASSWORD')


        # Initialize Neo4j driver
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    # Queries
    def get_hosts(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (s:System)
                RETURN COUNT(DISTINCT s.id) AS HostCount
                """
            )
            return result.single().value()

    def get_critical_hosts(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (s:System)
                WHERE s.critical > 0
                RETURN COUNT(DISTINCT s.id) AS CriticalHostCount
                """
            )
            return result.single().value()

    def get_findings(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n:Finding)
                RETURN COUNT(n) AS FindingCount
                """
            )
            return result.single().value()

    def get_vulnerabilities(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n:Vulnerability)
                RETURN COUNT(DISTINCT n.cve) AS VulnerabilityCount
                """
            )
            return result.single().value()

    def get_findings_by_severity(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n:Finding)
                RETURN n.severity AS Severity, COUNT(n) AS Count
                """
            )
            return pd.DataFrame([r.data() for r in result])

    def get_total_unique_findings(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n:Finding)
                RETURN COUNT(DISTINCT n.title) AS UniqueFindingsCount
                """
            )
            return result.single().value()

    def get_host_criticality_count(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (s:System)
                OPTIONAL MATCH (s)<-[:runs_on]-(a:Application)-[:related_weakness]->(f1:Finding)
                OPTIONAL MATCH (s)-[:related_weakness]->(f2:Finding)
                WITH s, COLLECT(f1) + COLLECT(f2) AS allFindings
                
                // Ensure that we handle cases where there are no findings
                WITH s, allFindings, CASE WHEN SIZE(allFindings) = 0 THEN 0 ELSE REDUCE(total = 0, f IN allFindings | 
                    total + CASE 
                        WHEN f.severity = "Low" AND f.known_exploited_vulnerability = "FALSE" THEN 1
                        WHEN f.severity = "Low" AND f.known_exploited_vulnerability = "TRUE" THEN 8
                        WHEN f.severity = "Medium" AND f.known_exploited_vulnerability = "FALSE" THEN 2
                        WHEN f.severity = "Medium" AND f.known_exploited_vulnerability = "TRUE" THEN 16
                        WHEN f.severity = "High" AND f.known_exploited_vulnerability = "FALSE" THEN 4
                        WHEN f.severity = "High" AND f.known_exploited_vulnerability = "TRUE" THEN 32
                        ELSE 0
                    END)
                END AS total_risk_score
                
                WITH CASE
                    WHEN s.critical = 1 THEN total_risk_score * 2
                    ELSE total_risk_score
                END AS total_risk_score
                
                WITH CASE 
                         WHEN total_risk_score = 0 THEN "N/A"
                         WHEN total_risk_score >= 32 THEN "Critical"
                         WHEN total_risk_score >= 16 THEN "High"
                         WHEN total_risk_score >= 8 THEN "Medium"
                         ELSE "Low"
                     END AS risk_level
                RETURN risk_level, COUNT(*) AS count
                ORDER BY count DESC
                """
            )
            return pd.DataFrame([r.data() for r in result])

    def get_host_criticality(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (s:System)
                OPTIONAL MATCH (s)<-[:runs_on]-(a:Application)-[:related_weakness]->(f1:Finding)
                OPTIONAL MATCH (s)-[:related_weakness]->(f2:Finding)
                WITH s, 
                     COLLECT(f1) + COLLECT(f2) AS all_findings
                UNWIND all_findings AS f
                WITH s, 
                     CASE 
                         WHEN f.severity = "Low" THEN 1
                         WHEN f.severity = "Medium" THEN 2
                         WHEN f.severity = "High" THEN 4
                         ELSE 0
                     END * 
                     CASE 
                         WHEN f.known_exploited_vulnerability = "TRUE" THEN 8
                         ELSE 1
                     END AS score,
                     s.critical AS Critical
                WITH s.id AS ID,
                     s.provider_name AS Provider,
                     s.type AS Type,
                     s.sub_type AS Sub_Type,
                     s.state AS State,
                     s.critical AS Critical,
                     SUM(score) AS Base_Risk_Score
                WITH ID,
                     Provider,
                     Type,
                     Sub_Type,
                     State,
                     Critical,
                     CASE 
                         WHEN Critical = 1 THEN Base_Risk_Score * 2
                         ELSE Base_Risk_Score
                     END AS Total_Risk_Score
                RETURN ID,
                       Type,
                       Sub_Type,
                       State,
                       Critical,
                       Total_Risk_Score,
                       CASE 
                           WHEN Total_Risk_Score >= 32 THEN "Critical"
                           WHEN Total_Risk_Score >= 16 THEN "High"
                           WHEN Total_Risk_Score >= 8 THEN "Medium"
                           ELSE "Low"
                       END AS risk_level
                ORDER BY Total_Risk_Score DESC LIMIT 10
                """
            )
            return pd.DataFrame([r.data() for r in result])

    def get_publishers(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (n:SoftwareInstallation)
                RETURN DISTINCT n.publisher AS Publisher
                """
            )
            return [r['Publisher'] for r in result]

    def get_products(self, publisher):
        with self.driver.session() as session:
            result = session.run(
                f"""
                MATCH (n:SoftwareInstallation)
                WHERE n.publisher = '{publisher}'
                RETURN DISTINCT n.product AS Product
                """
            )
            return [r['Product'] for r in result]

    def get_versions(self, publisher, product):
        with self.driver.session() as session:
            result = session.run(
                f"""
                MATCH (n:SoftwareInstallation)
                WHERE n.publisher = '{publisher}' AND n.product = '{product}'
                RETURN DISTINCT n.version AS Version
                ORDER BY Version DESC
                """
            )
            return [r['Version'] for r in result]

    def get_systems_by_cve_vulnerability(self, cve):
        with self.driver.session() as session:
            tableresult = session.run(
                f"""
                MATCH (v:Vulnerability)--(n:Weakness)--(s:System)
                WHERE v.cve = "{cve}" 
                WITH s
                OPTIONAL MATCH (s)<-[:runs_on]-(a:Application)-[:related_weakness]->(f1:Finding)
                OPTIONAL MATCH (s)-[:related_weakness]->(f2:Finding)
                WITH s, 
                     COLLECT(f1) + COLLECT(f2) AS all_findings
                UNWIND all_findings AS f
                WITH s, 
                     CASE 
                         WHEN f.severity = "Low" THEN 1
                         WHEN f.severity = "Medium" THEN 2
                         WHEN f.severity = "High" THEN 4
                         ELSE 0
                     END * 
                     CASE 
                         WHEN f.known_exploited_vulnerability = "TRUE" THEN 8
                         ELSE 1
                     END AS score,
                     s.critical AS Critical
                WITH s.id AS ID,
                     s.provider_name AS Provider,
                     s.type AS Type,
                     s.sub_type AS Sub_Type,
                     s.state AS State,
                     s.critical AS Critical,
                     SUM(score) AS Base_Risk_Score
                WITH ID,
                     Provider,
                     Type,
                     Sub_Type,
                     State,
                     Critical,
                     CASE 
                         WHEN Critical = 1 THEN Base_Risk_Score * 2
                         ELSE Base_Risk_Score
                     END AS Total_Risk_Score
                RETURN ID,
                       Type,
                       Sub_Type,
                       State,
                       Critical,
                       Total_Risk_Score,
                       CASE 
                           WHEN Total_Risk_Score >= 32 THEN "Critical"
                           WHEN Total_Risk_Score >= 16 THEN "High"
                           WHEN Total_Risk_Score >= 8 THEN "Medium"
                           ELSE "Low"
                       END AS risk_level
                ORDER BY Total_Risk_Score DESC LIMIT 10
                """
            )
            # Pie Chart
            pieresult = session.run(
                f"""
                MATCH (v:Vulnerability)--(n:Weakness)--(s:System)
                WHERE v.cve = "{cve}" 
                WITH s
                OPTIONAL MATCH (s)<-[:runs_on]-(a:Application)-[:related_weakness]->(f1:Finding)
                OPTIONAL MATCH (s)-[:related_weakness]->(f2:Finding)
                WITH s, COLLECT(f1) + COLLECT(f2) AS allFindings
                
                // Ensure that we handle cases where there are no findings
                WITH s, allFindings, CASE WHEN SIZE(allFindings) = 0 THEN 0 ELSE REDUCE(total = 0, f IN allFindings | 
                    total + CASE 
                        WHEN f.severity = "Low" AND f.known_exploited_vulnerability = "FALSE" THEN 1
                        WHEN f.severity = "Low" AND f.known_exploited_vulnerability = "TRUE" THEN 8
                        WHEN f.severity = "Medium" AND f.known_exploited_vulnerability = "FALSE" THEN 2
                        WHEN f.severity = "Medium" AND f.known_exploited_vulnerability = "TRUE" THEN 16
                        WHEN f.severity = "High" AND f.known_exploited_vulnerability = "FALSE" THEN 4
                        WHEN f.severity = "High" AND f.known_exploited_vulnerability = "TRUE" THEN 32
                        ELSE 0
                    END)
                END AS total_risk_score
                
                WITH CASE
                    WHEN s.critical = 1 THEN total_risk_score * 2
                    ELSE total_risk_score
                END AS total_risk_score
                
                WITH CASE 
                         WHEN total_risk_score = 0 THEN "N/A"
                         WHEN total_risk_score >= 32 THEN "Critical"
                         WHEN total_risk_score >= 16 THEN "High"
                         WHEN total_risk_score >= 8 THEN "Medium"
                         ELSE "Low"
                     END AS risk_level
                RETURN risk_level, COUNT(*) AS count
                ORDER BY count DESC
                """
            )

            return pd.DataFrame([r.data() for r in tableresult]), pd.DataFrame([r.data() for r in pieresult])

    def advanced_search(self, publishers, products=None, min_versions=None, max_versions=None):
        with self.driver.session() as session:
            # Ensure publishers, products, and versions are lists for iteration
            if products is None:
                products = [None] * len(publishers)
            if min_versions is None:
                min_versions = [None] * len(publishers)
            if max_versions is None:
                max_versions = [None] * len(publishers)

            # Generate conditions based on provided lists
            conditions = []
            for publisher, product, min_version, max_version in zip(publishers, products, min_versions, max_versions):
                condition = f"(n.publisher = '{publisher}'"
                if product is not None:
                    condition += f" AND n.product = '{product}'"
                if min_version is not None:
                    condition += f" AND n.version >= '{min_version}'"
                if max_version is not None:
                    condition += f" AND n.version <= '{max_version}'"
                condition += ")"
                conditions.append(condition)

            # Join all conditions using OR
            where_clause = " OR ".join(conditions)

            # Run the query
            result = session.run(
                f"""
                MATCH (n:SoftwareInstallation)
                WHERE {where_clause}
                WITH n AS software
                MATCH (software)--(s:System)
                OPTIONAL MATCH (s)<-[:runs_on]-(a:Application)-[:related_weakness]->(f1:Finding)
                OPTIONAL MATCH (s)-[:related_weakness]->(f2:Finding)
                WITH s, 
                     COLLECT(f1) + COLLECT(f2) AS all_findings
                UNWIND all_findings AS f
                WITH s, 
                     CASE 
                         WHEN f.severity = "Low" THEN 1
                         WHEN f.severity = "Medium" THEN 2
                         WHEN f.severity = "High" THEN 4
                         ELSE 0
                     END * 
                     CASE 
                         WHEN f.known_exploited_vulnerability = "TRUE" THEN 8
                         ELSE 1
                     END AS score,
                     s.critical AS Critical
                WITH s.id AS ID,
                     s.provider_name AS Provider,
                     s.type AS Type,
                     s.sub_type AS Sub_Type,
                     s.state AS State,
                     s.critical AS Critical,
                     SUM(score) AS Base_Risk_Score
                WITH ID,
                     Provider,
                     Type,
                     Sub_Type,
                     State,
                     Critical,
                     CASE 
                         WHEN Critical = 1 THEN Base_Risk_Score * 2
                         ELSE Base_Risk_Score
                     END AS Total_Risk_Score
                RETURN ID,
                       Type,
                       Sub_Type,
                       State,
                       Critical,
                       Total_Risk_Score,
                       CASE 
                           WHEN Total_Risk_Score >= 32 THEN "Critical"
                           WHEN Total_Risk_Score >= 16 THEN "High"
                           WHEN Total_Risk_Score >= 8 THEN "Medium"
                           ELSE "Low"
                       END AS risk_level
                ORDER BY Total_Risk_Score DESC LIMIT 10
                """
            )

            result_pie = session.run(
                f"""
                MATCH (n:SoftwareInstallation)
                WHERE {where_clause}
                WITH n AS software
                MATCH (software)--(s:System)
                OPTIONAL MATCH (s)<-[:runs_on]-(a:Application)-[:related_weakness]->(f1:Finding)
                OPTIONAL MATCH (s)-[:related_weakness]->(f2:Finding)
                WITH s, COLLECT(f1) + COLLECT(f2) AS allFindings
                
                // Ensure that we handle cases where there are no findings
                WITH s, allFindings, CASE WHEN SIZE(allFindings) = 0 THEN 0 ELSE REDUCE(total = 0, f IN allFindings | 
                    total + CASE 
                        WHEN f.severity = "Low" AND f.known_exploited_vulnerability = "FALSE" THEN 1
                        WHEN f.severity = "Low" AND f.known_exploited_vulnerability = "TRUE" THEN 8
                        WHEN f.severity = "Medium" AND f.known_exploited_vulnerability = "FALSE" THEN 2
                        WHEN f.severity = "Medium" AND f.known_exploited_vulnerability = "TRUE" THEN 16
                        WHEN f.severity = "High" AND f.known_exploited_vulnerability = "FALSE" THEN 4
                        WHEN f.severity = "High" AND f.known_exploited_vulnerability = "TRUE" THEN 32
                        ELSE 0
                    END)
                END AS total_risk_score
                
                WITH CASE
                    WHEN s.critical = 1 THEN total_risk_score * 2
                    ELSE total_risk_score
                END AS total_risk_score
                
                WITH CASE 
                         WHEN total_risk_score = 0 THEN "N/A"
                         WHEN total_risk_score >= 32 THEN "Critical"
                         WHEN total_risk_score >= 16 THEN "High"
                         WHEN total_risk_score >= 8 THEN "Medium"
                         ELSE "Low"
                     END AS risk_level
                RETURN risk_level, COUNT(*) AS count
                ORDER BY count DESC
                """
            )
            return pd.DataFrame([r.data() for r in result]), pd.DataFrame([r.data() for r in result_pie])

    def get_country_count(self):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (system)-[:in_country]->(country)
                RETURN country.name AS country, COUNT(system) AS count
                ORDER BY count DESC
                """
            )
            return pd.DataFrame([r.data() for r in result])
