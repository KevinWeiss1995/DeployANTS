FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV DEPLOYMENT_ENV=production

CMD ["python", "-m", "src.server.server"] 