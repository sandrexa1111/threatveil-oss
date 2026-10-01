# threatveil.com: prebuilt static pages (website/build.py) served by non-root nginx on :8080.
FROM nginxinc/nginx-unprivileged:1.31-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af
COPY nginx.conf /etc/nginx/nginx.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
COPY public/ /usr/share/nginx/html/
USER 101
EXPOSE 8080
