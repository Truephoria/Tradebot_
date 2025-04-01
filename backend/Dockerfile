FROM python:3.11
WORKDIR /app
# Install system dependencies required for psutil and ensure pip is available
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*
# Ensure pip is installed
RUN python3 -m ensurepip --upgrade \
    && python3 -m pip install --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["python", "app.py"]