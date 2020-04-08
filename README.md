# XOAuth example

> A lite version of XOAuth for example

XOAuth provides a simple way to interact with OpenId Connect identity providers from your local CLI. Many OIDC providers only support the Authorisation Code grant - and that means running a local web server to receive the authorisation response, or using something like [Postman](https://www.postman.com/). These can be tricky to fit into a scripted workflow in a shell.

This tool saves you time, by:

- Managing a local web server to receive the OpenId Connect callback
- Using [metadata discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) to build the Authorisation Request
- Verifying the token integrity with the providers's [JWKS](https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41) public keys

### Supported grant types

- [Authorisation code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)

### Example

`go run cmd/main.go`
