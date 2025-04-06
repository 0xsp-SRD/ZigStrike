
FROM python:3.11-slim

WORKDIR /zigstrike

COPY App /zigstrike/App

COPY src /zigstrike/src
COPY build.zig /zigstrike/build.zig


RUN pip install flask
RUN pip install Werkzeug

RUN apt-get update && \
    apt-get install -y wget xz-utils && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        wget https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz && \
        tar -xf zig-linux-x86_64-0.14.0.tar.xz && \
        mv zig-linux-x86_64-0.14.0 /usr/local/zig && \
        rm zig-linux-x86_64-0.14.0.tar.xz; \
    elif [ "$ARCH" = "aarch64" ]; then \
        wget https://ziglang.org/download/0.14.0/zig-linux-aarch64-0.14.0.tar.xz && \
        tar -xf zig-linux-aarch64-0.14.0.tar.xz && \
        mv zig-linux-aarch64-0.14.0 /usr/local/zig && \
        rm zig-linux-aarch64-0.14.0.tar.xz; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    ln -s /usr/local/zig/zig /usr/local/bin/zig

RUN mkdir -p /zigstrike/zig-out/bin


EXPOSE 5002


WORKDIR /zigstrike/App


CMD ["python", "app.py"]
