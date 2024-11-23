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

        # Load configuration
        config = configparser.ConfigParser()
        config.read(config_path)

        print(config)

        # Read connection details from config file
        uri = config['NEO4J']['URI']
        user = config['NEO4J']['USER']
        password = config['NEO4J']['PASSWORD']

        # Initialize Neo4j driver
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

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