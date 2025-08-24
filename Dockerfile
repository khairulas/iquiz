# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file to the working directory
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application's code to the working directory
COPY . .

# Make the run script executable
RUN chmod +x run.sh

# The port the app will run on within the container (Hugging Face standard)
EXPOSE 7860

# Command to run the application using our script
CMD ["bash", "run.sh"]