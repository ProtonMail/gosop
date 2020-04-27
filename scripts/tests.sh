#!/bin/bash

if (( $# != 3 || $2 != '-v' )); then
    echo "Usage: test.sh sop.binary -v <int verbosity>"
    exit 1
fi

sop=gosop
which $sop
if (( $? != 0 )); then
    echo "gosop not found."; echo
    echo "Did you run go install? Is \$GOPATH/bin in your \$PATH?"
    echo "... else, you can set sop=/path/to/gosop/binary in scripts/tests.sh"; echo
    exit 1
fi

verbosity=$3

# tmp directory, erased on exit
create_tmp_dir() {
    eval $1="$(mktemp -d)"
    if (( $? != 0 )); then
        echo "Failed to create temporary directory"
        exit $?
    fi
}

erase_tmp_dir() {
    rm -rf $1
    if (( $? != 0 )); then
        echo "Failed to delete temporary directory: $1"
        exit $?
    fi
}


check_exit_code() {
    if (( $1 == 69 || $1 == 37 )); then
        printf "    ... SKIPPED \n"
        return 0
    fi

    if (( $1 != $2 )); then
        echo "Failed: Exit code $1, expected $2"
        exit $1
    fi
    echo "    ... OK"
}

comm() {
    printf "$ $1\n"
}

my_cat() {
    if (( $verbosity == 1 )); then
        head -n1 $1
    fi
    if (( $verbosity == 2 )); then
        cat $1
    fi
}

create_tmp_dir data
trap "erase_tmp_dir $data" EXIT

# Test files
message=$data/message.txt
alice_secret=$data/alice.sec
bob_secret=$data/bob.sec
alice_public=$data/alice.asc
bob_public=$data/bob.asc
bob_public_unarmored=$data/bob.bin
session_key=$data/session.bin
encrypted=$data/encrypted.asc
encrypted_with_password=$data/encrypted_with_password.asc
verification=$data/verification.txt
bad_verification=$data/bad_verification.txt
verification_too_old=$data/verification_too_old.txt
verification_too_young=$data/verification_too_young.txt
decrypted_with_password=$data/decrypted_password.txt
decrypted_with_key=$data/decrypted.txt
decrypted_with_session_key=$data/decrypted.txt
unarmored=$data/unarmored.bin


comm "version"
$sop version
check_exit_code $? 0

comm "generate-key --no-armor"
$sop generate-key --no-armor 'Bob Lovelace <bob@openpgp.example>' > $bob_secret
check_exit_code $? 0

comm "generate-key --no-armor"
$sop generate-key --no-armor 'Bob Lovelace <bob@openpgp.example>' > $bob_secret
check_exit_code $? 0

comm "generate-key"
$sop generate-key 'Alice Lovelace <alice@openpgp.example>' > $alice_secret
check_exit_code $? 0
my_cat $alice_secret

comm "extract-cert"
$sop extract-cert < $alice_secret > $alice_public
check_exit_code $? 0
my_cat $alice_public

comm "extract-cert --no-armor"
$sop extract-cert --no-armor < $bob_secret > $bob_public_unarmored
check_exit_code $? 0

printf "\nOír la noche inmensa, más inmensa sin ella.\nY el verso cae al alma como al pasto el rocío.\n" > $message

comm "sign"
$sop sign --as=text $alice_secret < $message > $encrypted
check_exit_code $? 0
my_cat $encrypted

comm "verify"
$sop verify $encrypted $alice_public < $message > $verification
check_exit_code $? 0
my_cat $verification

comm "verify corrupt"
tr a-z A-Z < $message | $sop verify $encrypted $alice_public > $bad_verification
check_exit_code $? 3
my_cat $bad_verification

comm "verify --not-after"
$sop verify --not-after=20060102T150405Z $encrypted $alice_public < $message > $verification_too_old
check_exit_code $? 3
my_cat $verification_too_old

comm "verify --not-before"
$sop verify --not-before=now $encrypted $alice_public < $message > $verification_too_young
check_exit_code $? 3
my_cat $verification_too_young

comm "encrypt --with-password"
$sop encrypt --with-password=test.123 < $message > $encrypted_with_password
check_exit_code $? 0
my_cat $encrypted_with_password

comm "decrypt --with-password"
$sop decrypt --with-password=test.123 < $encrypted_with_password > $decrypted_with_password
check_exit_code $? 0
my_cat $decrypted_with_password

comm "encrypt"
$sop encrypt $alice_public < $message > $encrypted
check_exit_code $? 0
my_cat $encrypted

comm "decrypt"
$sop decrypt $alice_secret < $encrypted > $decrypted_with_key
check_exit_code $? 0
my_cat $decrypted_with_key

comm "decrypt --as=text --sign-with"
$sop encrypt --as=mime --sign-with=$alice_secret $alice_public < $message > $encrypted
check_exit_code $? 0
my_cat $encrypted

comm "decrypt --session-key-out --verify-with --verify-out"
$sop decrypt --session-key-out=$session_key --verify-with=$alice_public --verify-out=$verification $alice_secret < $encrypted > $decrypted_with_key
check_exit_code $? 0
my_cat $decrypted_with_key
my_cat $verification

comm "decrypt --with-session-key"
$sop decrypt --with-session-key=$session_key < $encrypted > $decrypted_with_session_key
check_exit_code $? 0
my_cat $decrypted_with_session_key

comm "armor"
$sop armor < $bob_public_unarmored > $bob_public
check_exit_code $? 0
my_cat $bob_public

comm "dearmor"
$sop dearmor < $encrypted > $unarmored
check_exit_code $? 0
