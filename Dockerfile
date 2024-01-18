# Docker image for compiling CST
FROM ubuntu:20.04

# Allow using a http proxy. It should be passed to docker build command using, eg:
# --build-arg http_proxy=$bamboo_capability_agent_http_proxy
ARG http_proxy
ARG hostUID=1000
ARG hostGID=1000
ARG hostUserName=cst

ENV http_proxy=$http_proxy

RUN dpkg --add-architecture i386

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
    gcc                     \
    make                    \
    git                     \
    byacc                   \
    flex                    \
    mingw-w64               \
    g++-multilib            \
    libssl-dev              \
    libssl-dev:i386         \
    libudev-dev             \
    libudev-dev:i386        \
    libusb-1.0-0-dev        \
    libusb-1.0-0-dev:i386

# Configure User ( use the host user's UID/GID )
RUN groupadd -f -g $hostGID $hostUserName
RUN useradd -g $hostGID -m -s /bin/bash -u $hostUID $hostUserName
USER $hostUserName

# Make sure .bashrc sources user .bash_profile
RUN echo 'alias ll="ls -la"' >> /home/$hostUserName/.bashrc
RUN echo 'if [ -f ~/.bash_profile ]; then' >> /home/$hostUserName/.bashrc
RUN echo '   . ~/.bash_profile' >> /home/$hostUserName/.bashrc
RUN echo 'fi' >> /home/$hostUserName/.bashrc

# Customize the terminal prompt
RUN mkdir /home/$hostUserName/bin
RUN echo 'export PS1="\[\033[01;33m\]<docker> \[\033[01;31m\]\W \[\033[00m\]$ "' >> /home/$hostUserName/.bash_profile

# Log the image creation date
RUN date > /home/$hostUserName/image-creation-date.txt

# Setup a work environment
ENV WORK_DIR /home/$hostUserName/cst/
RUN mkdir -p $WORK_DIR
WORKDIR $WORK_DIR
