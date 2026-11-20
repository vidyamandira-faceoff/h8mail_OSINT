FROM python:3-alpine

RUN apk add --update --no-cache git bash
WORKDIR /h8mail
COPY . .
RUN pip install --no-cache-dir .
ENTRYPOINT ["h8mail"]
CMD ["-h"]
