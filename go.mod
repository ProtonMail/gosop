module github.com/ProtonMail/gosop

require (
	github.com/ProtonMail/go-crypto v1.1.0-alpha.5.0.20240912135802-28c613e7c719
	github.com/ProtonMail/gopenpgp/v3 v3.0.0-alpha.4-proton.0.20240912140112-6bc60995ec03
	github.com/urfave/cli/v2 v2.2.0
)

require (
	github.com/cloudflare/circl v1.4.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
)

replace github.com/cloudflare/circl v1.4.0 => github.com/lubux/circl v0.0.0-20240912122524-f16d68fe1630
replace github.com/cloudflare/circl v1.3.7 => github.com/lubux/circl v0.0.0-20240912122524-f16d68fe1630

go 1.21

toolchain go1.21.6
