FROM python:3.8

RUN apt-get update && apt-get install -y gettext gcc default-libmysqlclient-dev python-dev

RUN pip install --upgrade pip poetry twine
RUN poetry config virtualenvs.create false

WORKDIR /usr/src/app

COPY pyproject.toml poetry.lock ./

RUN poetry install

COPY ./ ./
