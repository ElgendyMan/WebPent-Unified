FROM python:3.12-alpine
RUN pip install --no-cache-dir jinja2==3.1.4
COPY dashboard.py /app/dashboard.py
EXPOSE 9090
CMD ["python", "/app/dashboard.py"]
