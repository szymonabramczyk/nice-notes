FROM python:3.12-slim


WORKDIR /app

ARG SECRET_KEY
ARG MAIL_PASSWORD
ARG DEFAULT_MAIL_SENDER 

COPY . . 
RUN pip install -r requirements.txt

CMD gunicorn --bind 0.0.0.0:5000 main:app

