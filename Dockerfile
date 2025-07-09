FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy the entire repository and install it as a package
COPY . .
RUN pip install -e .

# Run the controller module properly
CMD ["kopf", "run", "--standalone", "-m", "controller.controller"]