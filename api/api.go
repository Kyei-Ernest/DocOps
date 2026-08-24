// Package api serves the OpenAPI specification and its interactive viewers:
// the raw spec at /openapi.yaml, Swagger UI at /docs, and Redoc at /redoc.
//
// The viewers are single static HTML pages pulling their JS/CSS from public
// CDNs — zero Go dependencies added, everything else in this binary remains
// stdlib-first per repo convention. The spec itself is go:embed'ed so the
// binary is self-contained: documentation ships with (and versions with) the
// code it describes.
package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var specYAML []byte

//go:embed static/swagger.html
var swaggerHTML []byte

//go:embed static/redoc.html
var redocHTML []byte

// Spec serves the raw OpenAPI document. Content-Type application/yaml so
// tooling (codegen, validators, curl) can consume it directly.
func Spec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Write(specYAML)
}

// SwaggerUI serves the interactive API explorer.
func SwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(swaggerHTML)
}

// Redoc serves the three-panel reference documentation view.
func Redoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(redocHTML)
}
