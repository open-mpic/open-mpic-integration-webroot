#!/usr/bin/env bash
 
#Usage: hashalg  [outputhex]
#Output Base64-encoded digest

DOMAIN_PATH="."
if [ -z "$TLS_CONF" ]; then
  TLS_CONF="$DOMAIN_PATH/tls.validation.conf"
fi
if [ -z "$TLS_CERT" ]; then
  TLS_CERT="$DOMAIN_PATH/tls.validation.cert"
fi
if [ -z "$TLS_KEY" ]; then
  TLS_KEY="$DOMAIN_PATH/tls.validation.key"
fi
if [ -z "$TLS_CSR" ]; then
  TLS_CSR="$DOMAIN_PATH/tls.validation.csr"
fi


_debug() {
    echo "$@"
}

_debug2() {
    echo "$@"
}

_info() {
    echo "$@"
}

_err() {
    echo "$@"
}

#identifier
_getIdType() {
  if _isIP "$1"; then
    echo "$ID_TYPE_IP"
  else
    echo "$ID_TYPE_DNS"
  fi
}

_upper_case() {
  # shellcheck disable=SC2018,SC2019
  tr '[a-z]' '[A-Z]'
}

_lower_case() {
  # shellcheck disable=SC2018,SC2019
  tr '[A-Z]' '[a-z]'
}

_startswith() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep -- "^$_sub" >/dev/null 2>&1
}

_endswith() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep -- "$_sub\$" >/dev/null 2>&1
}

_contains() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep -- "$_sub" >/dev/null 2>&1
}

_digest() {
  alg="$1"
  if [ -z "$alg" ]; then
    _usage "Usage: _digest hashalg"
    return 1
  fi

  outputhex="$2"

  if [ "$alg" = "sha256" ] || [ "$alg" = "sha1" ] || [ "$alg" = "md5" ]; then
    if [ "$outputhex" ]; then
      ${ACME_OPENSSL_BIN:-openssl} dgst -"$alg" -hex | cut -d = -f 2 | tr -d ' '
    else
      ${ACME_OPENSSL_BIN:-openssl} dgst -"$alg" -binary | _base64
    fi
  else
    _err "$alg is not supported yet"
    return 1
  fi

}



#ip
_isIPv4() {
  for seg in $(echo "$1" | tr '.' ' '); do
    _debug2 seg "$seg"
    if [ "$(echo "$seg" | tr -d '[0-9]')" ]; then
      #not all number
      return 1
    fi
    if [ $seg -ge 0 ] && [ $seg -lt 256 ]; then
      continue
    fi
    return 1
  done
  return 0
}

#ip6
_isIPv6() {
  _contains "$1" ":"
}

#ip
_isIP() {
  _isIPv4 "$1" || _isIPv6 "$1"
}

#domain
_is_idn() {
  _is_idn_d="$1"
  _idn_temp=$(printf "%s" "$_is_idn_d" | tr -d '[0-9]' | tr -d '[a-z]' | tr -d '[A-Z]' | tr -d '*.,-_')
  [ "$_idn_temp" ]
}

#aa.com
#aa.com,bb.com,cc.com
_idn() {
  __idn_d="$1"
  if ! _is_idn "$__idn_d"; then
    printf "%s" "$__idn_d"
    return 0
  fi

  if _exists idn; then
    if _contains "$__idn_d" ','; then
      _i_first="1"
      for f in $(echo "$__idn_d" | tr ',' ' '); do
        [ -z "$f" ] && continue
        if [ -z "$_i_first" ]; then
          printf "%s" ","
        else
          _i_first=""
        fi
        idn --quiet "$f" | tr -d "\r\n"
      done
    else
      idn "$__idn_d" | tr -d "\r\n"
    fi
  else
    _err "Please install idn to process IDN names."
  fi
}

#keylength or isEcc flag (empty str => not ecc)
_isEccKey() {
  _length="$1"

  if [ -z "$_length" ]; then
    return 1
  fi

  [ "$_length" != "1024" ] &&
    [ "$_length" != "2048" ] &&
    [ "$_length" != "3072" ] &&
    [ "$_length" != "4096" ] &&
    [ "$_length" != "8192" ]
}

# _createkey  2048|ec-256   file
_createkey() {
  length="$1"
  f="$2"
  echo "_createkey for file:$f"
  eccname="$length"
  if _startswith "$length" "ec-"; then
    length=$(printf "%s" "$length" | cut -d '-' -f 2-100)

    if [ "$length" = "256" ]; then
      eccname="prime256v1"
    fi
    if [ "$length" = "384" ]; then
      eccname="secp384r1"
    fi
    if [ "$length" = "521" ]; then
      eccname="secp521r1"
    fi

  fi

  if [ -z "$length" ]; then
    length=2048
  fi

  echo "Using length $length"

  if ! [ -e "$f" ]; then
    if ! touch "$f" >/dev/null 2>&1; then
      _f_path="$(dirname "$f")"
      echo _f_path "$_f_path"
      if ! mkdir -p "$_f_path"; then
        _err "Cannot create path: $_f_path"
        return 1
      fi
    fi
    if ! touch "$f" >/dev/null 2>&1; then
      return 1
    fi
    chmod 600 "$f"
  fi

  if _isEccKey "$length"; then
    echo "Using EC name: $eccname"
    if _opkey="$(${ACME_OPENSSL_BIN:-openssl} ecparam -name "$eccname" -noout -genkey 2>/dev/null)"; then
      echo "$_opkey" >"$f"
    else
      _err "Error encountered for ECC key named $eccname"
      return 1
    fi
  else
    echo "Using RSA: $length"
    __traditional=""
    if _contains "$(${ACME_OPENSSL_BIN:-openssl} help genrsa 2>&1)" "-traditional"; then
      __traditional="-traditional"
    fi
    if _opkey="$(${ACME_OPENSSL_BIN:-openssl} genrsa $__traditional "$length" 2>/dev/null)"; then
      echo "$_opkey" >"$f"
    else
      _err "Error encountered for RSA key of length $length"
      return 1
    fi
  fi

  if [ "$?" != "0" ]; then
    _err "Key creation error."
    return 1
  fi
}

#_createcsr  cn  san_list  keyfile csrfile conf acmeValidationv1
_createcsr() {
  echo "_createcsr"
  domain="$1"
  domainlist="$2"
  csrkey="$3"
  csr="$4"
  csrconf="$5"
  acmeValidationv1="$6"
  echo domain "$domain"
  echo domainlist "$domainlist"
  echo csrkey "$csrkey"
  echo csr "$csr"
  echo csrconf "$csrconf"

  printf "[ req_distinguished_name ]\n[ req ]\ndistinguished_name = req_distinguished_name\nreq_extensions = v3_req\n[ v3_req ]" >"$csrconf"

  if [ "$Le_ExtKeyUse" ]; then
    _savedomainconf Le_ExtKeyUse "$Le_ExtKeyUse"
    printf "\nextendedKeyUsage=$Le_ExtKeyUse\n" >>"$csrconf"
  else
    printf "\nextendedKeyUsage=serverAuth,clientAuth\n" >>"$csrconf"
  fi

  if [ "$acmeValidationv1" ]; then
    domainlist="$(_idn "$domainlist")"
    echo domainlist "$domainlist"
    alt=""
    for dl in $(echo "$domainlist" | tr "," ' '); do
      if [ "$alt" ]; then
        alt="$alt,DNS:$dl"
      else
        alt="DNS:$dl"
      fi
    done
    printf -- "\nsubjectAltName=$alt" >>"$csrconf"
  elif [ -z "$domainlist" ] || [ "$domainlist" = "$NO_VALUE" ]; then
    #single domain
    _info "Single domain" "$domain"
    printf -- "\nsubjectAltName=$(_getIdType "$domain" | _upper_case):$(_idn "$domain")" >>"$csrconf"
  else
    domainlist="$(_idn "$domainlist")"
    _debug2 domainlist "$domainlist"
    alt="$(_getIdType "$domain" | _upper_case):$(_idn "$domain")"
    for dl in $(echo "'$domainlist'" | sed "s/,/' '/g"); do
      dl=$(echo "$dl" | tr -d "'")
      alt="$alt,$(_getIdType "$dl" | _upper_case):$dl"
    done
    #multi
    _info "Multi domain" "$alt"
    printf -- "\nsubjectAltName=$alt" >>"$csrconf"
  fi
  if [ "$Le_OCSP_Staple" = "1" ]; then
    _savedomainconf Le_OCSP_Staple "$Le_OCSP_Staple"
    printf -- "\nbasicConstraints = CA:FALSE\n1.3.6.1.5.5.7.1.24=DER:30:03:02:01:05" >>"$csrconf"
  fi

  if [ "$acmeValidationv1" ]; then
    printf "\n1.3.6.1.5.5.7.1.31=critical,DER:04:20:${acmeValidationv1}" >>"${csrconf}"
  fi

  _csr_cn="$(_idn "$domain")"
  _debug2 _csr_cn "$_csr_cn"
  if _contains "$(uname -a)" "MINGW"; then
    if _isIP "$_csr_cn"; then
      ${ACME_OPENSSL_BIN:-openssl} req -new -sha256 -key "$csrkey" -subj "//O=$PROJECT_NAME" -config "$csrconf" -out "$csr"
    else
      ${ACME_OPENSSL_BIN:-openssl} req -new -sha256 -key "$csrkey" -subj "//CN=$_csr_cn" -config "$csrconf" -out "$csr"
    fi
  else
    if _isIP "$_csr_cn"; then
      ${ACME_OPENSSL_BIN:-openssl} req -new -sha256 -key "$csrkey" -subj "/O=$PROJECT_NAME" -config "$csrconf" -out "$csr"
    else
      ${ACME_OPENSSL_BIN:-openssl} req -new -sha256 -key "$csrkey" -subj "/CN=$_csr_cn" -config "$csrconf" -out "$csr"
    fi
  fi
}

#_signcsr key  csr  conf cert
_signcsr() {
  key="$1"
  csr="$2"
  conf="$3"
  cert="$4"
  _debug "_signcsr"

  _msg="$(${ACME_OPENSSL_BIN:-openssl} x509 -req -days 365 -in "$csr" -signkey "$key" -extensions v3_req -extfile "$conf" -out "$cert" 2>&1)"
  _ret="$?"
  _debug "$_msg"
  return $_ret
}



# _starttlsserver  san_a  san_b port content _ncaddr acmeValidationv1
_starttlsserver() {
  echo "Starting tls server."
  san_a="$1"
  san_b="$2"
  port="$3"
  content="$4"
  opaddr="$5"
  acmeValidationv1="$6"

  echo san_a "$san_a"
  echo san_b "$san_b"
  echo port "$port"
  echo acmeValidationv1 "$acmeValidationv1"

  #create key TLS_KEY
  if ! _createkey "2048" "$TLS_KEY"; then
    _err "Error creating TLS validation key."
    return 1
  fi

  #create csr
  alt="$san_a"
  if [ "$san_b" ]; then
    alt="$alt,$san_b"
  fi
  if ! _createcsr "tls.acme.sh" "$alt" "$TLS_KEY" "$TLS_CSR" "$TLS_CONF" "$acmeValidationv1"; then
    _err "Error creating TLS validation CSR."
    return 1
  fi

  #self signed
  if ! _signcsr "$TLS_KEY" "$TLS_CSR" "$TLS_CONF" "$TLS_CERT"; then
    _err "Error creating TLS validation cert."
    return 1
  fi

  __S_OPENSSL="${ACME_OPENSSL_BIN:-openssl} s_server -www -cert $TLS_CERT  -key $TLS_KEY "
  if [ "$opaddr" ]; then
    __S_OPENSSL="$__S_OPENSSL -accept $opaddr:$port"
  else
    __S_OPENSSL="$__S_OPENSSL -accept $port"
  fi


  if [ "$acmeValidationv1" ]; then
    __S_OPENSSL="$__S_OPENSSL -alpn acme-tls/1"
  fi

  echo "$__S_OPENSSL"
  if [ "$DEBUG" ] && [ "$DEBUG" -ge "2" ]; then
    $__S_OPENSSL -tlsextdebug &
  else
    $__S_OPENSSL >/dev/null 2>&1 &
  fi

  serverproc="$!"
  sleep 1
  echo serverproc "$serverproc"
}

keyauthorization="evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

acmevalidationv1="$(printf "%s" "$keyauthorization" | _digest "sha256" "hex")"


_ncaddr="0.0.0.0"
d="tls-alpn.integration-testing.open-mpic.org"

echo $acmevalidationv1
listenport=443
if ! _starttlsserver "$d" "" "$listenport" "$keyauthorization" "$_ncaddr" "$acmevalidationv1"; then
        _err "Error starting TLS server."
        _clearupwebbroot "$_currentRoot" "$removelevel" "$token"
        _clearup
        _on_issue_err "$_post_hook" "$vlist"
        return 1
fi