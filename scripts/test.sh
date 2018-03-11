#!/bin/env bash
#set -e

PORT=32123
export VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:$PORT"}
export VAULT_TOKEN=vault
export CONFDIR="$(git rev-parse --show-toplevel)/scripts"

if [ -z "$TMPDIR" ]; then
	export TMPDIR="$(mktemp -d)"

cp $CONFDIR/config.json $TMPDIR/
sed -i'' 's/PORT/'$PORT'/' $TMPDIR/config.json
sed -i'' 's#PLUGINDIR#'$TMPDIR'#' $TMPDIR/config.json
fi

vault-start() {
    vault server -dev -dev-root-token-id "$VAULT_TOKEN" -config "$TMPDIR/config.json" -log-level=trace &
    echo "Vault started"
    sleep 1
    vault login $VAULT_TOKEN
}

vault-stop() {
    pkill vault
}

vault-provision-users() {
    if vault auth enable userpass ; then
        echo "Enabled userpass auth backend"
    fi
    for user in m.conraux b.ooba f.cents; do
        vault write /auth/userpass/users/$user password=a
    done
}

vault-update-plugin() {
    NAME=test-plugin
    go build -o ./a.out .
    mkdir -p $TMPDIR/
    mv ./a.out $TMPDIR/${NAME}
    sum=$(shasum -a256 $TMPDIR/${NAME} | awk '{print $1}')
    if [ -z ${sum} ]; then
        echo "Could not sha sum the file ${NAME}"
    fi
    vault policy write default $CONFDIR/default.hcl
    vault write /sys/plugins/catalog/${NAME} sha256=${sum} command=${NAME}
    vault secrets disable test-cove
    vault secrets enable -path test-cove -plugin-name $NAME  -local plugin
}
