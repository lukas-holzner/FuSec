# FuSec 🔐

![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Streamlit](https://img.shields.io/badge/streamlit-1.46.1-red.svg)
![Neo4j](https://img.shields.io/badge/neo4j-5.28.1-blue.svg)
![Docker](https://img.shields.io/badge/docker-enabled-blue.svg)

**FuSec** is a comprehensive security vulnerability management and analysis platform developed for the **Siemens Challenge** at [HackaTUM 2025](https://hack.tum.de/). This tool provides security teams with powerful insights into vulnerability landscapes, risk assessment, and AI-powered mitigation strategies.

## 🚀 Features

- **📊 Security Dashboard**: Real-time visualization of vulnerability metrics, host criticality, and risk levels
- **🔍 CVE Analysis**: Integration with NIST vulnerability database for detailed CVE information
- **🎯 Risk Assessment**: Automated scoring system for hosts and applications based on vulnerability severity
- **🤖 AI-Powered Mitigations**: Intelligent mitigation suggestions using Groq API, including Ansible playbooks
- **🌍 Geographic Analysis**: Visualization of vulnerability distribution across different regions
- **🔬 Advanced Investigation**: Multi-parameter search and filtering capabilities for vulnerability research
- **📈 Interactive Visualizations**: Dynamic charts and graphs powered by Plotly for data exploration

## 🛠️ Technologies Used

- **Backend**: Python 3.11, Neo4j Graph Database
- **Frontend**: Streamlit Web Framework
- **Visualization**: Plotly, Pandas
- **AI Integration**: Groq API for intelligent mitigations
- **Data Sources**: NIST CVE Database
- **Deployment**: Docker, Python Package Manager

## 📋 Prerequisites

- Python 3.11 or higher
- Neo4j Database (local or remote)
- Groq API key (for AI-powered mitigations)
- Docker (optional, for containerized deployment)

## 🚀 Quick Start

### Option 1: Local Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/lukas-holzner/FuSec.git
   cd FuSec
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the application**
   Create a `src/config.ini` file with your database and API settings:
   ```ini
   [NEO4J]
   URI = bolt://localhost:7687
   USER = neo4j
   PASSWORD = your_password
   
   [GROQ]
   API_KEY = your_groq_api_key
   ```

4. **Run the application**
   ```bash
   streamlit run src/1_General.py
   ```

5. **Access the dashboard**
   Open your browser and navigate to `http://localhost:8501`

### Option 2: Docker Deployment

1. **Build the Docker image**
   ```bash
   docker build -t fusec .
   ```

2. **Run the container**
   ```bash
   docker run -p 8501:8501 \
     -e NEO4J_URI=bolt://your-neo4j-host:7687 \
     -e NEO4J_USER=neo4j \
     -e NEO4J_PASSWORD=your_password \
     -e GROQ_API_KEY=your_groq_api_key \
     fusec
   ```

## 📖 Usage

### 1. General Dashboard 📊
- View overall security metrics including total hosts, critical systems, and vulnerability counts
- Analyze vulnerability distribution by severity levels
- Monitor geographic spread of security issues

### 2. Investigation Tools 🔍
- **CVE Search**: Look up specific Common Vulnerabilities and Exposures
- **Advanced Filtering**: Search by software publishers, products, and version ranges
- **Risk Analysis**: Identify high-risk systems and applications
- **Host Criticality**: Evaluate system importance and exposure levels

### 3. Mitigation Assistance 🤖
- Input CVE details to receive AI-generated mitigation strategies
- Get both automated Ansible playbooks and manual step-by-step guides
- Access NIST database integration for comprehensive vulnerability information

## 📁 Project Structure

```
FuSec/
├── src/
│   ├── 1_General.py              # Main dashboard application
│   ├── pages/
│   │   ├── 2_Investigation.py    # Investigation and search tools
│   │   └── 3_Mitigations.py      # AI-powered mitigation suggestions
│   ├── database/
│   │   ├── connection.py         # Neo4j database connection and queries
│   │   └── nist.py              # NIST CVE database integration
│   ├── visualization/
│   │   └── dashboard.py         # Dashboard components and charts
│   └── config.ini               # Configuration file (create manually)
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Container configuration
└── README.md                   # This file
```

## 🔧 Configuration

### Environment Variables

For Docker deployment or when `config.ini` is not available:

- `NEO4J_URI`: Neo4j database connection URI
- `NEO4J_USER`: Neo4j database username
- `NEO4J_PASSWORD`: Neo4j database password
- `GROQ_API_KEY`: Groq API key for AI-powered features

### Database Setup

FuSec requires a Neo4j graph database with the following node types:
- `System`: Represents hosts and infrastructure
- `Application`: Software applications running on systems
- `Vulnerability`: CVE entries and security issues
- `Finding`: Security findings and assessments
- `Weakness`: Security weaknesses and vulnerabilities

## 🤝 Contributing

We welcome contributions to FuSec! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add appropriate documentation for new features
- Include tests for new functionality
- Update README.md if needed

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏆 Credits

**FuSec** was developed as part of the **Siemens Challenge** at [HackaTUM 2025](https://hack.tum.de/), one of Europe's largest hackathons focused on technology and innovation.

### Team Contributors
- Development team focused on cybersecurity and vulnerability management
- Special thanks to the Siemens Challenge organizers and mentors
- HackaTUM 2025 organizing committee

### Third-Party Libraries
- [Streamlit](https://streamlit.io/) - Web application framework
- [Neo4j](https://neo4j.com/) - Graph database platform
- [Plotly](https://plotly.com/) - Interactive visualization library
- [Groq](https://groq.com/) - AI inference platform
- [NIST](https://nvd.nist.gov/) - National Vulnerability Database

## 🐛 Issues and Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/lukas-holzner/FuSec/issues) page
2. Create a new issue with detailed description
3. Include system information and error messages

## 🔮 Future Enhancements

- Integration with additional vulnerability databases
- Advanced machine learning models for risk prediction
- Real-time vulnerability scanning capabilities
- Enhanced reporting and export features
- Multi-tenant support for enterprise deployment

---

*Built with ❤️ for cybersecurity professionals at HackaTUM 2025*