module UnAutoIt

go 1.15

require (
	github.com/dustin/go-humanize v1.0.0
	github.com/gosuri/uilive v0.0.4 // indirect
	github.com/gosuri/uiprogress v0.0.1
	github.com/h2non/filetype v1.1.0
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/olekukonko/tablewriter v0.0.4
	github.com/spf13/cobra v1.1.1
	github.com/spf13/viper v1.7.1
	github.com/x0r19x91/libautoit v1.2.8
)

// libautoit is no longer on GitHub or proxy.golang.org; a lightly patched copy
// of v1.2.8 (h1:t+FeR+oN0wxG3clOVG0Kx19GGY203U7JlXXjjuOku1k=) lives in
// third_party, see third_party/README.md.
replace github.com/x0r19x91/libautoit => ./third_party/libautoit
