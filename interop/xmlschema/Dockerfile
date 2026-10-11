# xmlschema (MIT), an independent XSD 1.0 processor, for the cap interop
# tests.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir xmlschema==3.4.3
COPY validate.py /opt/validate.py
ENTRYPOINT ["python", "/opt/validate.py"]
