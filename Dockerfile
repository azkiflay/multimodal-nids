FROM tensorflow/tensorflow:latest-gpu
# FROM python:latest
WORKDIR /app
# Set the environment variable for the schema name
ENV POSTGRES_SCHEMA_NAME=public

RUN apt-get update && apt-get install -y \
    texlive-full \
    texlive-latex-extra \
    texlive-fonts-recommended \
    dvipng \
    tshark && \
    rm -rf /var/lib/apt/lists/*
# Install Python and TensorFlow
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
RUN pip3 install -U scikit-learn
RUN pip3 install yellowbrick

EXPOSE 8000  
COPY app /app
# RUN chmod -R 766 ../data # Error: chmod: cannot access '../data': No such file or directory
# Set the command to run the TensorFlow application
CMD ["python3", "main.py"]