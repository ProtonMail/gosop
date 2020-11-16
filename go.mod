module github.com/ProtonMail/gosop

require (
	github.com/ProtonMail/gopenpgp/v2 v2.1.1
	github.com/urfave/cli/v2 v2.2.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20201112134528-b4bfec6bba36

go 1.14
