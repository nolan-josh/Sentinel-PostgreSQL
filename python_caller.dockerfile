# Dockerfile 

# the -slim means the image version that the 
# python verison runs on top of 
FROM python:3.12-slim 

# Set the working directory inside the container 
WORKDIR /python_scripts
# Copy the Python script into the container's working directory 
COPY /scripts/live_data_generator.py /python_scripts
COPY /scripts/data_generator.py /python_scripts

RUN pip install pymongo faker

# command to run when the container starts 
CMD ["python", "-u", "/python_scripts/live_data_generator.py"]