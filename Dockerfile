FROM python:3

# Copy the app source and set up dependencies
RUN apt-get update -y
RUN pip install requests
RUN apt-get install -y nmap dnsutils
COPY monitor_network.py /app/monitor_network.py

# Run the app
CMD ["python", "/app/monitor_network.py"]