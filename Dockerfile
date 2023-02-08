FROM python:3

# Copy the app source and set up dependencies
RUN pip install requests
COPY monitor_network.py /app/monitor_network.py

# Run the app
CMD ["python", "/app/monitor_network.py"]