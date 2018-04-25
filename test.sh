#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NOC='\033[0m'
ALREADY_ENC="Already Encrypted"
SECRETS_REPO="https://github.com/futuresimple/helm-secrets"
HELM_CMD="helm-wrapper"

trap_error() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        echo -e "${RED}General error${NOC}" 1>&2
        exit 1
    else
        exit 0
    fi
    echo -e "${RED}General error${NOC}" 1>&2
}

trap "trap_error" EXIT

test_encryption() {
result=$(cat < "${secret}" | grep -Ec "(40B6FAEC80FD467E3FE9421019F6A67BB1B8DDBE|4434EA5D05F10F59D0DF7399AF1D073646ED4927)")
if [ "${result}" -eq 2 ] && [ "${secret}" == "./example/helm_vars/secrets.yaml" ];
then
    echo -e "${GREEN}[OK]${NOC} File properly encrypted" 1>&2
elif [ "${result}" -eq 1 ] && [ "${secret}" != "./example/helm_vars/secrets.yaml" ];
then
    echo -e "${GREEN}[OK]${NOC} File properly encrypted" 1>&2
else
    echo -e "${RED}[FAIL]${NOC} ${secret} Not encrypted properly" 1>&2
    exit 1
fi
}

test_view() {
result_view=$(${HELM_CMD} secrets view "${secret}" | grep -Ec "(40B6FAEC80FD467E3FE9421019F6A67BB1B8DDBE|4434EA5D05F10F59D0DF7399AF1D073646ED4927)")
if [ "${result_view}" -gt 0 ];
then
    echo -e "${RED}[FAIL]${NOC} Decryption failed" 1>&2
else
    echo -e "${GREEN}[OK]${NOC} File decrypted and viewable" 1>&2
fi
}

test_decrypt() {
if [ -f "${secret}.dec" ];
then
    result_dec=$(cat < "${secret}.dec" | grep -Ec "(40B6FAEC80FD467E3FE9421019F6A67BB1B8DDBE|4434EA5D05F10F59D0DF7399AF1D073646ED4927)")
    if [ "${result_dec}" -gt 0 ];
    then
        echo -e "${RED}[FAIL]${NOC} Decryption failed" 1>&2
    else
        echo -e "${GREEN}[OK]${NOC} File decrypted" 1>&2
    fi
else
    echo -e "${RED}[FAIL]${NOC} ${secret}.dec not exist" 1>&2
    exit 1
fi
}

test_clean() {
if [ -f "${secret}.dec" ];
then
    echo -e "${RED}[FAIL]${NOC} ${secret}.dec exist after cleanup" 1>&2
    exit 1
else
    echo -e "${GREEN}[OK]${NOC} Cleanup ${mode}" 1>&2
fi
}

test_already_encrypted() {
if [[ "${enc_res}" == *"${ALREADY_ENC}"* ]];
then
    echo -e "${GREEN}[OK]${NOC} Already Encrypted" 1>&2
else
    echo -e "${RED}[FAIL]${NOC} Not Encrypted or re-encrypted. Should be already encrypted with no re-encryption." 1>&2
    exit 1
fi
}


test_helm_secrets() {
echo -e "${YELLOW}+++${NOC} ${BLUE}Testing ${secret}${NOC}" 1>&2

echo -e "${YELLOW}+++${NOC} Encrypt and Test" 1>&2
"${HELM_CMD}" secrets enc "${secret}" > /dev/null || exit 1 && \
test_encryption "${secret}"

echo -e "${YELLOW}+++${NOC} Test if 'Already Encrypted' feature works" 1>&2
enc_res=$("${HELM_CMD}" secrets enc "${secret}" | grep "${ALREADY_ENC}")
test_already_encrypted "${enc_res}"

echo -e "${YELLOW}+++${NOC} View encrypted Test" 1>&2
test_view "${secret}"

echo -e "${YELLOW}+++${NOC} Decrypt" 1>&2
"${HELM_CMD}" secrets dec "${secret}" > /dev/null || exit 1 && \
test_decrypt "${secret}" && \
cp "${secret}.dec" "${secret}"

echo -e "${YELLOW}+++${NOC} Cleanup Test" 1>&2
"${HELM_CMD}" secrets clean "$(dirname ${secret})" > /dev/null || exit 1
mode="specified directory"
test_clean "${secret}" "${mode}" && \
cp "${secret}" "${secret}.dec" && \
"${HELM_CMD}" secrets clean "${secret}.dec" > /dev/null || exit 1
mode="specified .dec file"
test_clean "${secret}" "${mode}" && \
cp "${secret}" "${secret}.dec" && \
"${HELM_CMD}" secrets clean "${secret}" > /dev/null || exit 1
mode="specified encrypted secret file"
test_clean "${secret}" "${mode}"

echo -e "${YELLOW}+++${NOC} Once again Encrypt and Test" 1>&2
"${HELM_CMD}" secrets enc "${secret}" > /dev/null || exit 1 && \
test_encryption "${secret}"
}

echo -e "${YELLOW}+++${NOC} Installing helm-secrets plugin" 1>&2
if [ "$(helm plugin list | tail -n +2 | cut -d ' ' -f 1 | grep -c "secrets")" -eq 1 ];
then
    echo -e "${GREEN}[OK]${NOC} helm-ecrets plugin installed" 1>&2
else
    "${HELM_CMD}" plugin install "${SECRETS_REPO}" 2>/dev/null
    echo -e "${RED}[FAIL]${NOC} No helm-secrets plugin aboting" 1>&2
    exit 1
fi

echo "" 1>&2
if [ -x "$(command -v gpg --version)" ];
then
    echo -e "${YELLOW}+++${NOC} Importing private pgp key for projectx" 1>&2
    gpg --import example/pgp/projectx.asc
    echo "" 1>&2
    echo -e "${YELLOW}+++${NOC} Importing private pgp key for projectx" 1>&2
    gpg --import example/pgp/projecty.asc
    echo ""
else
    echo -e "${RED}[FAIL]${NOC} Install gpg" 1>&2
    exit 1
fi

echo -e "${YELLOW}+++${NOC} Show helm_vars tree from example" 1>&2
if [ -x "$(command -v tree --version)" ];
then
    tree -Ca example/helm_vars/
else
    echo -e "${RED}[FAIL]${NOC} Install tree command" 1>&2
    exit 1
fi

echo "" 1>&2
for secret in $(find . -type f -name secrets.yaml);
do test_helm_secrets "${secret}";
done
