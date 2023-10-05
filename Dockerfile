FROM ubuntu:22.04
WORKDIR /app
ENV POSTGRES_SCHEMA_NAME=public
RUN apt-get update && apt-get install -y \
    texlive-full \
    texlive-latex-extra \
    texlive-fonts-recommended \
    dvipng \
    tshark && \
    rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
RUN pip3 install -U scikit-learn
EXPOSE 8000  
COPY app /app
CMD ["python3", "main.py"]
