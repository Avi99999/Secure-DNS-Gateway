# Unbound resolver image for the Secure DNS Gateway (Windows / macOS hosts).
FROM alpine:3.20

RUN apk add --no-cache unbound ca-certificates drill \
 && mkdir -p /var/lib/unbound \
 && chown unbound:unbound /var/lib/unbound

COPY docker.conf /etc/unbound/unbound.conf

# Refresh the DNSSEC root trust anchor, validate the config, then run in the foreground.
CMD ["/bin/sh", "-c", "su -s /bin/sh unbound -c 'unbound-anchor -a /var/lib/unbound/root.key' ; unbound-checkconf && exec unbound -d -c /etc/unbound/unbound.conf"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD drill -p 5335 @127.0.0.1 example.com > /dev/null || exit 1
