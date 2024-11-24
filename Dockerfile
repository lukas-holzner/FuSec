# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY src/ ./src/

# Expose the port Streamlit runs on
EXPOSE 8501

# Set environment variables (if config.ini is not used)
ENV NEO4J_URI=bolt://neo4j:7687
ENV NEO4J_USER=neo4j
ENV NEO4J_PASSWORD=password
ENV GROQ_API_KEY=your-api-key

# Command to run the application
CMD ["streamlit", "run", "src/1_General.py", "--server.address", "0.0.0.0"]