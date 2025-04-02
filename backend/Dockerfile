FROM python:3.11
WORKDIR /app
# Install system dependencies required for psutil and ensure pip is available
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*
# Ensure pip is installed and available in PATH
RUN python3 -m ensurepip --upgrade \
    && python3 -m pip install --upgrade pip \
    && ln -sf /usr/local/bin/pip /usr/bin/pip  # Ensure pip is in /usr/bin
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]