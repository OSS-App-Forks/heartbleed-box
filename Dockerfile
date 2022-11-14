FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y build-essential git aria2

RUN aria2c "https://github.com/openssl/openssl/archive/refs/tags/OpenSSL_1_0_1f.tar.gz"

RUN tar xf openssl-OpenSSL_1_0_1f.tar.gz

RUN cd /openssl-OpenSSL_1_0_1f && \
    ./config enable-ssl-trace

RUN cd /openssl-OpenSSL_1_0_1f && \
    make && \
    make install_sw

RUN cp /openssl-OpenSSL_1_0_1f/apps/openssl /openssl && \
    rm -rf /openssl-OpenSSL_1_0_1f

RUN apt purge -y build-essential
RUN apt autoremove -y && apt clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN /openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=IN/ST=KA/L=Mangalore/O=localhost/CN=localhost"

ENTRYPOINT /openssl s_server -key key.pem -cert cert.pem -accept 4433 -www -status_verbose