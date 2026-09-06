# Deliberately misconfigured, used as IaC scanner ground truth (AS-030).
FROM ubuntu:20.04

# Runs as root: no USER instruction anywhere in this file.
RUN apt-get update && apt-get install -y curl

# A secret baked into an image layer, where it survives every later deletion.
ENV API_KEY="sk-live-not-a-real-key-000000000000"

COPY . /app
EXPOSE 22
CMD ["/app/run.sh"]
