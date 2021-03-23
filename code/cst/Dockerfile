# Docker image for compiling CST (on Ubuntu 16.04)
FROM ubuntu:16.04

WORKDIR /opt/cst-repo/cst

# Allow using a http proxy. It should be passed to docker build command using, eg:
# --build-arg http_proxy=$bamboo_capability_agent_http_proxy
ARG http_proxy
ENV http_proxy=$http_proxy


RUN echo 'alias ll="ls -la"' >> ~/.bashrc && \
    date > /opt/image-creation-date.txt

RUN dpkg --add-architecture i386

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    gcc                     \
    make                    \
    git                     \
    byacc                   \
    flex                    \
    mingw-w64               \
    g++-multilib            \
    preprocess              \
    libssl-dev              \
    libssl-dev:i386         \
    libudev-dev             \
    libudev-dev:i386        \
    libusb-1.0-0-dev        \
    libusb-1.0-0-dev:i386

