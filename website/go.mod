// Hugo Modules are Go modules: this file exists only to pin the documentation theme, with
// checksums in go.sum. It is intentionally separate from the plugin's go.mod so the theme never
// enters the plugin's module graph (go mod tidy, NOTICE.md, govulncheck).
//
// No Go code is compiled here, so the go directive only needs to satisfy the theme's own
// requirement (Hextra declares go 1.21).
module github.com/eclipse-keysealer/k8s-kms-plugin/website

go 1.21

require github.com/imfing/hextra v0.12.3
