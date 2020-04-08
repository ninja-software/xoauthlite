package xoauthexample

// TokenResultViewModel holds data for the web result
type TokenResultViewModel struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Claims       interface{}
	Authority    string
}

// TokenResultView template for the web result
func TokenResultView() string {
	return `
<!doctype html>
<html>
	<head>
		<title>XOAuth</title>
		<style>
			body {
				font-family: sans-serif;
				margin: 3em;
			}
		</style>
	</head>
	<body>
		<h3>OpenId Connect credentials</h3>
		<p>Authority: {{.Authority}}</p>
		<ul>
			<li>
				access token: {{.AccessToken}}
			</li>
			<li>
				refresh token: {{.RefreshToken}}
			</li>
			<li>
				identity token: {{.IDToken}}
			</li>
		</ul>
		
		<h3>ID Token Claims</h3>
		
		{{ range $key, $value := .Claims }}
		   <li><strong>{{ $key }}</strong>: {{ $value }}</li>
		{{ end }}
		
		<p>✅ You can close this window now.</p>
	</body>
</html>
`
}
