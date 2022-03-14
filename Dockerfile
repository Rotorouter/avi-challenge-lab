ARG PYTHON_VER=3.9
FROM python:${PYTHON_VER}-slim AS cli

WORKDIR /usr/src/app

# Install poetry for dep management
RUN apt-get update && apt-get install -yq curl certbot python3-certbot-dns-cloudflare
RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python
ENV PATH="$PATH:/root/.poetry/bin"

# Install project manifest
COPY pyproject.toml poetry.lock ./

# Install production dependencies
RUN poetry config virtualenvs.create false \
  && poetry install --no-interaction --no-ansi --no-dev

COPY avi_challenge_lab/ ./

ENTRYPOINT ["python3"]
CMD ["cli.py"]
