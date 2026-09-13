# threatveil.com: prebuilt static pages (website/build.py) served by non-root nginx on :8080.
FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6
COPY nginx.conf /etc/nginx/nginx.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
COPY public/ /usr/share/nginx/html/
USER 101
EXPOSE 8080
