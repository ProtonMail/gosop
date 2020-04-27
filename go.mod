module github.com/ProtonMail/gosop

require (
	github.com/ProtonMail/gopenpgp/v2 v2.0.1-0.20200427190123-222decb91901
	github.com/urfave/cli/v2 v2.2.0
	golang.org/x/crypto v0.0.0-20190923035154-9ee001bba392
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20200420072808-71bec3603bf3

go 1.14
