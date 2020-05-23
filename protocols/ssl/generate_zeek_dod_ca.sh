#!/bin/bash -eu

set -o pipefail

export CERT_URL='https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/certificates_pkcs7_v5-6_dod.zip'
export WCF_URL='https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_v5-8_wcf.zip'

# Download & Extract DoD root certificates
/usr/bin/curl -s -LOJ ${CERT_URL}
/usr/bin/curl -s -LOJ ${WCF_URL}

/usr/bin/unzip -o "$(basename ${CERT_URL})" >/dev/null
/usr/bin/unzip -o "$(basename ${WCF_URL})" >/dev/null

cd "$(/usr/bin/zipinfo -1 "$(basename ${CERT_URL})" | /usr/bin/awk -F/ '{ print $1 }' | head -1)"

cat << EOF
# Don't edit!  This file is automatically generated.
# Generated at: $(date +%FT%T%z)
# Generated from: ${CERT_URL}, ${WCF_URL}
#
# The original source files are published by the US Department of Defense at
# the URLS listed above and are public-domain.

@load base/protocols/ssl
module SSL;
redef root_certs += {
EOF

declare subj
declare bytes

# Convert pem.p7b certs to straight pem and import
for item in *.pem.p7b; do
  TOPDIR="$(pwd)"
  TMPDIR="$(mktemp -d /tmp/"$(basename "${item}" .p7b)".XXXXXX)" || exit 1
  PEMNAME="$(basename "${item}" .p7b)"
  openssl pkcs7 -print_certs -in "${item}" -out "${TMPDIR}/${PEMNAME}"
  cd "${TMPDIR}"
  /usr/bin/split -p '^$' "${PEMNAME}"
  rm "$(ls x* | tail -1)"
  for cert in x??; do

    subj=$(openssl x509 -noout -subject -nameopt RFC2253 -in "${cert}" | sed 's/^subject= //')
    bytes=$(openssl x509 -outform DER -in "${cert}"| xxd -i | tr -d '\n' | sed 's/ 0x/\\x/g; s/[ ,]//g' | tr 'a-f' 'A-F')
    cat << EOF
    ["${subj}"] = "${bytes}",
EOF
  done
  
  cd "${TOPDIR}"
  rm -rf "${TMPDIR}"
done

cd ..

cd "$(/usr/bin/zipinfo -1 "$(basename ${WCF_URL})" | /usr/bin/awk -F/ '{ print $1 }' | head -1)"

# Convert pem.p7b certs to straight pem and import
for item in *.pem.p7b; do
  TOPDIR="$(pwd)"
  TMPDIR=$(mktemp -d /tmp/"$(basename "${item}" .p7b)".XXXXXX) || exit 1
  PEMNAME="$(basename "${item}" .p7b)"
  openssl pkcs7 -print_certs -in "${item}" -out "${TMPDIR}/${PEMNAME}"
  cd "${TMPDIR}"
  /usr/bin/split -p '^$' "${PEMNAME}"
  rm "$(ls x* | tail -1)"
  for cert in x??; do

    subj=$(openssl x509 -noout -subject -nameopt RFC2253 -in "${cert}" | sed 's/^subject= //')
    bytes=$(openssl x509 -outform DER -in "${cert}"| xxd -i | tr -d '\n' | sed 's/ 0x/\\x/g; s/[ ,]//g' | tr 'a-f' 'A-F')
    cat << EOF
    ["${subj}"] = "${bytes}",
EOF
  done
  
  cd "${TOPDIR}"
  rm -rf "${TMPDIR}"
done

echo "};"
