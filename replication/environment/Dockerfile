# Minimal image for the Fase 1 official run. Build from the package root (the folder holding code/):
#   docker build -f environment/Dockerfile -t fase1-oficial .
#   docker run --rm -v "$PWD/out:/work/code/results/fase1_oficial_docker" fase1-oficial \
#       scripts/reproduce_official.sh --no-venv --out /work/code/results/fase1_oficial_docker [--smoke]
FROM python:3.9.6-slim
WORKDIR /work
COPY environment/requirements.lock environment/requirements.lock
RUN pip install --no-cache-dir -r environment/requirements.lock
COPY . .
ENTRYPOINT ["bash"]
