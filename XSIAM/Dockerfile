# Base Stage: Install Dependencies
FROM demisto/python3:3.11.10.116949

RUN apk --update add --no-cache swig

RUN apk --update add --no-cache --virtual .build-dependencies gcc \
  musl-dev python3-dev libffi-dev openssl-dev wget git build-base linux-headers

COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
