FROM python:3.10-bullseye
COPY requirements.txt /app/
WORKDIR /app
RUN pip install -r requirements.txt
COPY . .
VOLUME /app/instance
CMD ["flask", "run", "-p", "9090", "-h", "0.0.0.0"]