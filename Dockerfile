FROM ubuntu:24.04 AS smoketest-ubuntu

RUN apt-get update \
    && apt-get install -y unzip python3 gcc libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY ./sv-sanitizers.zip .
RUN unzip sv-sanitizers.zip

WORKDIR /root/sv-sanitizers
RUN ./smoketest.sh

FROM registry.gitlab.com/sosy-lab/benchmarking/competition-scripts/user:2026 AS smoketest-competition

RUN apt-get update \
    && apt-get install -y unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
COPY ./sv-sanitizers.zip .
RUN unzip sv-sanitizers.zip

WORKDIR /root/sv-sanitizers
RUN ./smoketest.sh
