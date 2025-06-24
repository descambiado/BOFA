
FROM python:3.9-slim

WORKDIR /app

# Install requirements
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy generator code
COPY . .

# Create output directory
RUN mkdir -p output templates

EXPOSE 5000

CMD ["python", "app.py"]
