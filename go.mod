module github.com/ProtonMail/gosop

go 1.22.0

require (
	github.com/ProtonMail/go-crypto v1.3.1-0.20250527221502-355ec9cf3ce7
	github.com/ProtonMail/gopenpgp/v3 v3.3.1-0.20250527223103-e12c4d3d4250
	github.com/urfave/cli/v2 v2.2.0
)

require (
	github.com/cloudflare/circl v1.6.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/cloudflare/circl v1.6.0 => github.com/ProtonMail/circl v0.0.0-20250505075934-8c9cec5c8dd7
