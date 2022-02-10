# gosop

Stateless Command-Line Interface implementation for
[GopenPGP](https://gopenpgp.org).

### What is SOP?

The [Stateless OpenPGP
CLI](https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-01), known as
SOP, is an RFC specification that aims to provide a minimal API for any
implementation of the OpenPGP protocol, in the form of a command-line
Interface. SOP can be used to test interoperability between different
implementations of OpenPGP; the [OpenPGP interoperability Test
Suite](https://tests.sequoia-pgp.org/) reports results using several SOP
implementations. For more information, please refer to the
[specification](https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-01).

### Install
```
mkdir -p $GOPATH/src/github.com/ProtonMail/
cd $GOPATH/src/github.com/ProtonMail/
git clone git@github.com:ProtonMail/gosop.git && cd gosop
go install
```

You can now invoke `gosop` from your command line:
```
echo "Hello PGP" | gosop encrypt --with-password=PASSWORD_FILE
```
or:
```
echo "Hello PGP" | PWD="password" gosop encrypt --with-password="@ENV:PWD"
```
### Test your installation
Given the CLI nature of `gosop`, tests are run with `bash` scripts
outside the Go testing framework.
```
cd $GOPATH/src/github.com/ProtonMail/gosop
make test
```

### Usage

Invoke `gosop` followed by subcommands
```
$ gosop version
GopenPGP v2.1.1
```

See [commands directory](https://github.com/ProtonMail/gosop/tree/master/cmd)
for all currently supported subcommands and flags, or run `gosop help`.

### Contribute
If you are providing new commands or flags according to the
[specification](https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-01),
please add the appropriate tests and lint before submitting:
```
go install -u golang.org/x/lint/golint
go install github.com/golangci/golangci-lint/cmd/golangci-lint
make lint
```
