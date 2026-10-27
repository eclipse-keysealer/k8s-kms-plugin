# Pinned by digest for reproducible, tamper-evident builds (OpenSSF Scorecard
# Pinned-Dependencies). debian:unstable is a rolling tag; the digest below is
# the multi-arch index digest. Refresh with:
#   docker buildx imagetools inspect debian:unstable --format '{{.Manifest.Digest}}'
FROM debian:unstable@sha256:ac638695600796dac818dd0a79ef04147649eca20368daaf3add2ab7a0e08ae0
ARG cvclientpackage="cvclient-min.tar.gz"
ADD ${cvclientpackage} /opt/cvclient/
ADD inject.sh /inject-pkcs11-driver

ENTRYPOINT ["/inject-pkcs11-driver"]
