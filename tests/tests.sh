#!/bin/bash
# Runs basic tests.

set -eu
export SECRETS=../../../../../bin/secrets

# Verifies that help output displays.
${SECRETS} --help 2>&1 | grep -q "managing secrets"
${SECRETS} 2>&1 | grep -q "required flag"

# Verifies that empty files are handled correctly, 
# and that we can read from a YML file.
[[ "0" == "$(${SECRETS} -f /dev/null list | wc -l)" ]]
${SECRETS} -f does_not_exist.yml list && echo fail && exit 1 || /bin/true
[[ "0" == "$(${SECRETS} -f does_not_exist.yml list | wc -l)" ]]
[[ "1" == "$(${SECRETS} -f single.yml list | wc -l)" ]]
[[ "bar" == "$(${SECRETS} -f single.yml get name1)" ]]

# Verifies that we can write and read from a yaml file.
STORE=$(mktemp)
TMPA=$(mktemp)
TMPB=$(mktemp)
rm -rf ${TMPA} ${TMPB} ${STORE}
trap "rm -fr ${TMPA} ${TMPB} ${STORE}" EXIT

# Verify that we can store and retrieve secrets.
${SECRETS} -f ${STORE} put -p testing -k _ key1 value1
${SECRETS} -f ${STORE} put -p testing key2 value2
${SECRETS} -f ${STORE} put -p testing key3 value3
echo value4 > ${TMPA}
${SECRETS} -f ${STORE} put -p testing key4 -i ${TMPA}
[[ "value1" == "$(${SECRETS} -f ${STORE} get key1)" ]] 
[[ "value2" == "$(${SECRETS} -f ${STORE} get key2)" ]]
[[ "value3" == "$(${SECRETS} -f ${STORE} get key3)" ]]
[[ "value4" == "$(${SECRETS} -f ${STORE} get key4)" ]]
${SECRETS} -f ${STORE} get key1 -o ${TMPA}
[[ "value1" == "$(cat ${TMPA})" ]]

# Verify file IO works for larger text secrets.
${SECRETS} -f ${STORE} put -p testing shellscript -i $0
cmp $0 <(${SECRETS} -f ${STORE} get shellscript)
${SECRETS} -f ${STORE} get shellscript -o ${TMPA}
cmp ${TMPA} $0

# Verify file IO works for larger binary secrets.
gzip -c $0 > ${TMPA}
${SECRETS} -f ${STORE} put -p testing binary -i ${TMPA}
${SECRETS} -f ${STORE} get binary -o ${TMPB}
cmp -s ${TMPA} ${TMPB}
gzip -t ${TMPB}

# Verify that JSON support works.
[[ "1" == "$(${SECRETS} -f single.json list | wc -l)" ]]
[[ "bar" == "$(${SECRETS} -f single.json get name1)" ]]

echo '> TESTS PASS <'
