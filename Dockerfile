FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3-pip \
    python3.10-dev \
    build-essential \
    git \
    wget \
    curl \
    nmap \
    libpcap-dev \
    libssl-dev \
    unzip \
    cargo \
    iputils-ping \
    golang-go \
    chromium-browser \
    chromium-chromedriver \
    postgresql-server-dev-all \
    libpq-dev \
    xvfb \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/chromium-browser /usr/bin/chrome

# Install Go 1.21 for x86_64
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOARCH=amd64
ENV GOOS=linux

# Install feroxbuster using pre-built binary and ensure it's in PATH
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash && \
    ln -s /root/.cargo/bin/feroxbuster /usr/local/bin/feroxbuster

# Install ffuf using Go
RUN go install -v github.com/ffuf/ffuf/v2@latest

# Install nuclei using Go
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Install Playwright and its dependencies
RUN pip3 install playwright && \
    playwright install chromium && \
    playwright install-deps chromium

# Copy project
COPY . .

# Ensure wordlists directory exists and copy wordlist
RUN mkdir -p /app/scanner/wordlists
COPY scanner/wordlists/fuzzboom.txt /app/scanner/wordlists/
COPY scanner/wordlists/test.txt /app/scanner/wordlists/

# Expose port
EXPOSE 8000

# Make sure Go binaries are in PATH
ENV PATH="/root/go/bin:${PATH}"

# Add Chrome environment variables
ENV CHROME_BIN=/usr/bin/chrome
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver
ENV DISPLAY=:99

# Update any references to bugbrewer in the Dockerfile if they exist
ENV DJANGO_SETTINGS_MODULE=bugbrewer.settings
