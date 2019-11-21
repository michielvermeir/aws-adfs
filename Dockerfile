FROM python:3.8-slim-buster

COPY . aws_adfs

RUN mkdir -p /home/.aws/
COPY .example.config /home/.aws/config

RUN pip install aws_adfs/ awscli

ENTRYPOINT [ "aws" ]