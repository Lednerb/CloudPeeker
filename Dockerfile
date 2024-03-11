FROM python:3.10-alpine

# RUN apt-get update && apt-get install -y inetutils-traceroute

RUN pip install pipenv

WORKDIR /app

COPY Pipfile Pipfile.lock ./

RUN pipenv install --system --deploy

COPY . .

WORKDIR /data

ENTRYPOINT ["python", "/app/aio.py"]
