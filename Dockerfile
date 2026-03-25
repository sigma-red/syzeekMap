FROM python:3.12-slim

WORKDIR /app

# Install curl for downloading D3.js
RUN apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Vendor D3.js locally (critical for air-gapped deployment)
RUN mkdir -p /app/static/lib && \
    curl -sL https://d3js.org/d3.v7.min.js -o /app/static/lib/d3.v7.min.js

# Copy application code
COPY . .

# Ensure the local D3.js reference is used (overwrite CDN link in index.html)
RUN sed -i 's|https://d3js.org/d3.v7.min.js|/static/lib/d3.v7.min.js|' /app/static/index.html

EXPOSE 8080

CMD ["python", "app.py"]
