{{- define "toStr" -}}
    {{- $e := .RuntimeParams.expr -}}
    {{- $t := .RuntimeParams.goType -}}
    {{- if .RuntimeParams.isEnum -}}{{ $e }}.String()
    {{- else if eq $t "string" -}}{{ $e }}
    {{- else if eq $t "time.Time" -}}{{ $e }}.Format(time.RFC3339)
    {{- else if eq $t "uuid.UUID" -}}{{ $e }}.String()
    {{- else if eq $t "bool" -}}strconv.FormatBool({{ $e }})
    {{- else if eq $t "int" -}}strconv.Itoa({{ $e }})
    {{- else if eq $t "int32" -}}strconv.FormatInt(int64({{ $e }}), 10)
    {{- else if eq $t "int16" -}}strconv.FormatInt(int64({{ $e }}), 10)
    {{- else if eq $t "int64" -}}strconv.FormatInt({{ $e }}, 10)
    {{- else if eq $t "float32" -}}strconv.FormatFloat(float64({{ $e }}), 'f', -1, 32)
    {{- else if eq $t "float64" -}}strconv.FormatFloat({{ $e }}, 'f', -1, 64)
    {{- else -}}fmt.Sprintf("%v", {{ $e }})
    {{- end -}}
{{- end -}}

{{- define "authScheme" -}}
    {{- $scheme := .RuntimeParams.scheme -}}
    {{- $mode := .RuntimeParams.mode -}}
    {{- $s := index $.API.Components.SecuritySchemes $scheme -}}
    {{- $c := camel $scheme -}}
    {{- $kind := "apiKey" -}}
    {{- if eq $s.Value.Type "http" -}}
        {{- if eq $s.Value.Scheme "basic" -}}{{ $kind = "basic" }}{{- else -}}{{ $kind = "bearer" }}{{- end -}}
    {{- else if eq $s.Value.Type "oauth2" -}}
        {{- if and (isNotNil $s.Value.Flows) (isNotNil $s.Value.Flows.ClientCredentials) -}}{{ $kind = "clientCredentials" }}{{- else -}}{{ $kind = "authCode" }}{{- end -}}
    {{- else if eq $s.Value.Type "openIdConnect" -}}{{ $kind = "authCode" }}{{- end -}}

    {{- if eq $mode "params" -}}
        {{- if eq $kind "basic" }} {{ $c }}Username string, {{ $c }}Password string,
        {{- else if eq $kind "authCode" }} {{ $c }}Token *oauth2.Token,
        {{- else if eq $kind "clientCredentials" }}
        {{- else }} {{ $c }}Token string,
        {{- end -}}
    {{- else if eq $mode "provided" -}}
        {{- if eq $kind "basic" -}}{{ $c }}Username != ""
        {{- else if eq $kind "authCode" -}}{{ $c }}Token != nil
        {{- else if eq $kind "clientCredentials" -}}c.{{ $c }}Config != nil
        {{- else -}}{{ $c }}Token != ""
        {{- end -}}
    {{- else if eq $mode "field" -}}
        {{- if eq $kind "basic" }}
	{{ $c }}Username string
	{{ $c }}Password string
        {{- else if eq $kind "authCode" }}
	{{ $c }}Config oauth2.Config
        {{- else if eq $kind "clientCredentials" }}
	{{ $c }}Config *clientcredentials.Config
        {{- else }}
	{{ $c }}Token string
        {{- end }}
    {{- else if eq $mode "option" -}}
        {{- if eq $kind "basic" }}
func With{{ pascal $scheme }}Credentials(username, password string) ClientOption {
	return func(c *Client) {
		c.{{ $c }}Username = username
		c.{{ $c }}Password = password
	}
}
        {{- else if eq $kind "authCode" }}
func With{{ pascal $scheme }}Config(config oauth2.Config) ClientOption {
	return func(c *Client) {
		c.{{ $c }}Config = config
	}
}
        {{- else if eq $kind "clientCredentials" }}
func With{{ pascal $scheme }}Config(config clientcredentials.Config) ClientOption {
	return func(c *Client) {
		c.{{ $c }}Config = &config
	}
}
        {{- else }}
func With{{ pascal $scheme }}Token(token string) ClientOption {
	return func(c *Client) {
		c.{{ $c }}Token = token
	}
}
        {{- end }}
    {{- else if eq $mode "resolve" -}}
        {{- if eq $kind "basic" }}
	if {{ $c }}Username == "" {
		{{ $c }}Username = c.{{ $c }}Username
		{{ $c }}Password = c.{{ $c }}Password
	}
        {{- else if or (eq $kind "authCode") (eq $kind "clientCredentials") }}
        {{- else }}
	if {{ $c }}Token == "" {
		{{ $c }}Token = c.{{ $c }}Token
	}
        {{- end }}
    {{- else if eq $mode "inject" -}}
        {{- if eq $kind "bearer" }}
	if {{ $c }}Token != "" {
		req.Header.Set("Authorization", "Bearer "+{{ $c }}Token)
	}
        {{- else if eq $kind "basic" }}
	if {{ $c }}Username != "" {
		req.SetBasicAuth({{ $c }}Username, {{ $c }}Password)
	}
        {{- else if eq $kind "apiKey" }}
	if {{ $c }}Token != "" {
            {{- if eq $s.Value.In "header" }}
		req.Header.Set("{{ $s.Value.Name }}", {{ $c }}Token)
            {{- else if eq $s.Value.In "query" }}
		q := req.URL.Query()
		q.Set("{{ $s.Value.Name }}", {{ $c }}Token)
		req.URL.RawQuery = q.Encode()
            {{- else if eq $s.Value.In "cookie" }}
		req.AddCookie(&http.Cookie{Name: "{{ $s.Value.Name }}", Value: {{ $c }}Token})
            {{- end }}
	}
        {{- end }}
    {{- else if eq $mode "client" -}}
        {{- if eq $kind "authCode" }}
	if {{ $c }}Token != nil {
		doer = c.{{ $c }}Config.Client(context.WithValue(ctx, oauth2.HTTPClient, c.doer), {{ $c }}Token)
	}
        {{- else if eq $kind "clientCredentials" }}
	if c.{{ $c }}Config != nil {
		doer = c.{{ $c }}Config.Client(context.WithValue(ctx, oauth2.HTTPClient, c.doer))
	}
        {{- end }}
    {{- end -}}
{{- end -}}

{{- define "clientMethodSignature"}}
    {{- $path := .RuntimeParams.path -}}
    {{- $op := .RuntimeParams.op -}}
    {{- $package := .RuntimeParams.package -}}
    {{- $body := .GetRequestBody $op -}}
    {{- range $scheme := $.OpSecuritySchemes $op }}{{ template "authScheme" ($.WithParams "scheme" $scheme "mode" "params") }}{{- end }}
    {{- range $param := $.OpParams $path $op -}}
        {{- $name := print $op.OperationID " " $param.Value.Name -}}
        {{- if notEmpty $param.Ref }}{{ $name = trimPrefix "#/components/parameters/" $param.Ref }}{{ end -}}
        {{ goToken (camel $param.Value.Name) -}}
        {{- if $.ParamIsOptionalType $param }} *{{ end }} {{ $.GetType $package $name $param.Value.Schema }},
    {{- end -}}
    {{- if isNotNil $body}}
        {{- $type := $.GetType $package (print $op.OperationID " Request") $body.Schema }} body {{ $type  -}}
    {{- end -}}
    ) (
    {{- $response := $.GetOpHappyResponseType $package $op}}
    {{- if notEmpty $response}}{{ $.CheckPackage $response $package}}, {{ end }}error)
{{- end -}}

{{- $package := $.PackageName }}

// Code generated by foji {{ version }}, template: {{ templateFile }}; DO NOT EDIT.

package {{ $package }}

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
{{- .CheckAllTypes $package ($.Params.GetWithDefault "Auth" "") -}}
{{- range .GoImports }}
	"{{ . }}"
{{- end }}
)

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

type ClientOption func(*Client)

type Client struct {
	baseURL string
	doer    Doer
{{- range $security, $value := .API.Components.SecuritySchemes }}{{ template "authScheme" ($.WithParams "scheme" $security "mode" "field") }}{{- end }}
}

func NewClient(baseURL string, doer Doer, opts ...ClientOption) *Client {
	c := &Client{baseURL: baseURL, doer: doer}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

{{- range $security, $value := .API.Components.SecuritySchemes }}
{{ template "authScheme" ($.WithParams "scheme" $security "mode" "option") }}
{{- end }}

{{- if .HasAuthentication }}
var ErrMissingAuthToken = errors.New("missing auth token")
{{- end }}

type APIError struct {
	StatusCode int
	Status     string
	Body       []byte
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.StatusCode, e.Status, string(e.Body))
}

{{- range $name, $path := .API.Paths.Map }}
    {{- range $verb, $op := $path.Operations }}
        {{- $body := $.GetRequestBody $op }}
        {{- $opResponse := $.GetOpHappyResponse $package $op }}
        {{- $respType := $opResponse.GoType }}
        {{- $errRet := "" }}
        {{- if notEmpty $respType }}{{ if eq $respType "string" }}{{ $errRet = "\"\", " }}{{ else }}{{ $errRet = "nil, " }}{{ end }}{{ end }}

{{ goDoc (pascal $op.OperationID) }}
{{- goDoc $op.Summary }}
{{- goDoc $op.Description }}
func (c *Client) {{ pascal $op.OperationID }}(ctx context.Context,
    {{- template "clientMethodSignature" ($.WithParams "op" $op "package" $package "path" $path) }} {
        {{- range $scheme := $.OpSecuritySchemes $op }}{{ template "authScheme" ($.WithParams "scheme" $scheme "mode" "resolve") }}{{- end }}
        {{- if $.HasAnyAuth $op }}
            {{- $groups := $.OpSecurityGroups $op }}
            {{- $optional := false }}
            {{- range $g := $groups }}{{ if eq (len $g) 0 }}{{ $optional = true }}{{ end }}{{ end }}
            {{- if not $optional }}

	if !({{ range $i, $g := $groups }}{{ if $i }} || {{ end }}({{ range $j, $scheme := $g }}{{ if $j }} && {{ end }}{{ template "authScheme" ($.WithParams "scheme" $scheme "mode" "provided") }}{{ end }}){{ end }}) {
		return {{ $errRet }}ErrMissingAuthToken
	}
            {{- end }}
        {{- end }}

	u := c.baseURL + "{{ $name }}"
        {{- $hasQuery := false }}
        {{- range $param := $.OpParams $path $op }}{{ if eq $param.Value.In "query" }}{{ $hasQuery = true }}{{ end }}{{ end }}
        {{- if $hasQuery }}
	queryParams := url.Values{}
        {{- end }}
        {{- range $param := $.OpParams $path $op }}
            {{- $pName := $param.Value.Name }}
            {{- $var := goToken (camel $pName) }}
            {{- $tName := print $op.OperationID " " $pName }}
            {{- if notEmpty $param.Ref }}{{ $tName = trimPrefix "#/components/parameters/" $param.Ref }}{{ end }}
            {{- $goType := $.GetType $package $tName $param.Value.Schema }}
            {{- $isArray := $param.Value.Schema.Value.Type.Is "array" }}
            {{- $isEnum := $.ParamIsEnum $param }}
            {{- if $isArray }}
                {{- $elemType := $.StripArray $goType }}
                {{- $isArrayEnum := $.ParamIsEnumArray $param }}
                {{- if eq $param.Value.In "query" }}
	for _, v := range {{ $var }} {
		queryParams.Add("{{ $pName }}", {{ template "toStr" ($.WithParams "expr" "v" "goType" $elemType "isEnum" $isArrayEnum) }})
	}
                {{- end }}
            {{- else if $.ParamIsOptionalType $param }}
                {{- $deref := print "(*" $var ")" }}
	if {{ $var }} != nil {
                {{- if eq $param.Value.In "query" }}
		queryParams.Set("{{ $pName }}", {{ template "toStr" ($.WithParams "expr" $deref "goType" $goType "isEnum" $isEnum) }})
                {{- end }}
	}
            {{- else }}
                {{- if eq $param.Value.In "path" }}
	u = strings.Replace(u, "{{ printf "{%s}" $pName }}", url.PathEscape({{ template "toStr" ($.WithParams "expr" $var "goType" $goType "isEnum" $isEnum) }}), 1)
                {{- else if eq $param.Value.In "query" }}
	queryParams.Set("{{ $pName }}", {{ template "toStr" ($.WithParams "expr" $var "goType" $goType "isEnum" $isEnum) }})
                {{- end }}
            {{- end }}
        {{- end }}
        {{- if $hasQuery }}

	if len(queryParams) > 0 {
		u += "?" + queryParams.Encode()
	}
        {{- end }}

        {{- if isNotNil $body }}
            {{- if $body.IsJson }}

	buf, err := json.Marshal(body)
	if err != nil {
		return {{ $errRet }}fmt.Errorf("marshal request body: %w", err)
	}

	reqBody := bytes.NewReader(buf)
	contentType := "application/json"
            {{- else if $body.IsText }}

	reqBody := strings.NewReader(body)
	contentType := "text/plain"
            {{- else if $body.IsForm }}

	form := url.Values{}
                {{- range $field, $schemaProp := $.SchemaProperties $body.Schema }}
                    {{- $fGoType := $.GetType $package (print $op.OperationID " " $field) $schemaProp }}
                    {{- $fVar := print "body." (pascal $field) }}
                    {{- $fIsPtr := and (not ($.IsRequiredProperty $field $body.Schema)) $schemaProp.Value.Nullable }}
                    {{- if $schemaProp.Value.Type.Is "array" }}
	for _, v := range {{ $fVar }} {
		form.Add("{{ $field }}", {{ template "toStr" ($.WithParams "expr" "v" "goType" ($.StripArray $fGoType) "isEnum" ($.SchemaIsEnumArray $schemaProp)) }})
	}
                    {{- else if $fIsPtr }}
	if {{ $fVar }} != nil {
		form.Set("{{ $field }}", {{ template "toStr" ($.WithParams "expr" (print "(*" $fVar ")") "goType" $fGoType "isEnum" ($.SchemaIsEnum $schemaProp)) }})
	}
                    {{- else }}
	form.Set("{{ $field }}", {{ template "toStr" ($.WithParams "expr" $fVar "goType" $fGoType "isEnum" ($.SchemaIsEnum $schemaProp)) }})
                    {{- end }}
                {{- end }}

	reqBody := strings.NewReader(form.Encode())
	contentType := "application/x-www-form-urlencoded"
            {{- else if $body.IsMultipartForm }}

	var bodyBuf bytes.Buffer

	mw := multipart.NewWriter(&bodyBuf)
                {{- range $field, $schemaProp := $.SchemaProperties $body.Schema }}
                    {{- $fGoType := $.GetType $package (print $op.OperationID " " $field) $schemaProp }}
                    {{- $fVar := print "body." (pascal $field) }}
                    {{- $fRequired := $.IsRequiredProperty $field $body.Schema }}
                    {{- $fIsPtr := and (not $fRequired) $schemaProp.Value.Nullable }}
                    {{- if eq $fGoType "forms.File" }}
	{{ if not $fRequired }}if {{ $fVar }}.File != nil { {{ end -}}
	{
		part, err := mw.CreateFormFile("{{ $field }}", {{ $fVar }}.Filename)
		if err != nil {
			return {{ $errRet }}fmt.Errorf("multipart file {{ $field }}: %w", err)
		}

		if _, err := io.Copy(part, {{ $fVar }}.File); err != nil {
			return {{ $errRet }}fmt.Errorf("multipart file {{ $field }}: %w", err)
		}
	}
	{{- if not $fRequired }} }{{ end }}
                    {{- else if $schemaProp.Value.Type.Is "array" }}
	for _, v := range {{ $fVar }} {
		if err := mw.WriteField("{{ $field }}", {{ template "toStr" ($.WithParams "expr" "v" "goType" ($.StripArray $fGoType) "isEnum" ($.SchemaIsEnumArray $schemaProp)) }}); err != nil {
			return {{ $errRet }}fmt.Errorf("multipart field {{ $field }}: %w", err)
		}
	}
                    {{- else if $fIsPtr }}
	if {{ $fVar }} != nil {
		if err := mw.WriteField("{{ $field }}", {{ template "toStr" ($.WithParams "expr" (print "(*" $fVar ")") "goType" $fGoType "isEnum" ($.SchemaIsEnum $schemaProp)) }}); err != nil {
			return {{ $errRet }}fmt.Errorf("multipart field {{ $field }}: %w", err)
		}
	}
                    {{- else }}
	if err := mw.WriteField("{{ $field }}", {{ template "toStr" ($.WithParams "expr" $fVar "goType" $fGoType "isEnum" ($.SchemaIsEnum $schemaProp)) }}); err != nil {
		return {{ $errRet }}fmt.Errorf("multipart field {{ $field }}: %w", err)
	}
                    {{- end }}
                {{- end }}

	if err := mw.Close(); err != nil {
		return {{ $errRet }}fmt.Errorf("multipart close: %w", err)
	}

	reqBody := &bodyBuf
	contentType := mw.FormDataContentType()
            {{- end }}
        {{- end }}

	req, err := http.NewRequestWithContext(ctx, "{{ $verb }}", u, {{ if isNotNil $body }}reqBody{{ else }}http.NoBody{{ end }})
	if err != nil {
		return {{ $errRet }}err
	}
        {{- if isNotNil $body }}

	req.Header.Set("Content-Type", contentType)
        {{- end }}
        {{- range $param := $.OpParams $path $op }}
            {{- $pName := $param.Value.Name }}
            {{- $var := goToken (camel $pName) }}
            {{- $tName := print $op.OperationID " " $pName }}
            {{- if notEmpty $param.Ref }}{{ $tName = trimPrefix "#/components/parameters/" $param.Ref }}{{ end }}
            {{- $goType := $.GetType $package $tName $param.Value.Schema }}
            {{- $isEnum := $.ParamIsEnum $param }}
            {{- if eq $param.Value.In "header" }}
                {{- if $.ParamIsOptionalType $param }}

	if {{ $var }} != nil {
		req.Header.Set("{{ $pName }}", {{ template "toStr" ($.WithParams "expr" (print "(*" $var ")") "goType" $goType "isEnum" $isEnum) }})
	}
                {{- else }}

	req.Header.Set("{{ $pName }}", {{ template "toStr" ($.WithParams "expr" $var "goType" $goType "isEnum" $isEnum) }})
                {{- end }}
            {{- else if eq $param.Value.In "cookie" }}
                {{- if $.ParamIsOptionalType $param }}

	if {{ $var }} != nil {
		req.AddCookie(&http.Cookie{Name: "{{ $pName }}", Value: {{ template "toStr" ($.WithParams "expr" (print "(*" $var ")") "goType" $goType "isEnum" $isEnum) }}})
	}
                {{- else }}

	req.AddCookie(&http.Cookie{Name: "{{ $pName }}", Value: {{ template "toStr" ($.WithParams "expr" $var "goType" $goType "isEnum" $isEnum) }}})
                {{- end }}
            {{- end }}
        {{- end }}

        {{- range $scheme := $.OpSecuritySchemes $op }}{{ template "authScheme" ($.WithParams "scheme" $scheme "mode" "inject") }}{{- end }}

        {{- $opHasOAuth := false }}
        {{- range $scheme := $.OpSecuritySchemes $op }}{{ $s := index $.API.Components.SecuritySchemes $scheme }}{{ if or (eq $s.Value.Type "oauth2") (eq $s.Value.Type "openIdConnect") }}{{ $opHasOAuth = true }}{{ end }}{{ end }}
        {{- if $opHasOAuth }}
	doer := c.doer
            {{- range $scheme := $.OpSecuritySchemes $op }}{{ template "authScheme" ($.WithParams "scheme" $scheme "mode" "client") }}{{- end }}

	resp, err := doer.Do(req)
        {{- else }}

	resp, err := c.doer.Do(req)
        {{- end }}
	if err != nil {
		return {{ $errRet }}err
	}
        {{- if ne $respType "io.Reader" }}
	defer resp.Body.Close()
        {{- end }}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        {{- if eq $respType "io.Reader" }}
		defer resp.Body.Close()
        {{- end }}
		errBody, _ := io.ReadAll(resp.Body)

		return {{ $errRet }}&APIError{StatusCode: resp.StatusCode, Status: resp.Status, Body: errBody}
	}

        {{- if eq $respType "" }}

	return nil
        {{- else if $opResponse.MimeType.IsJson }}
            {{- if hasPrefix "*" $respType }}

	var out {{ trimPrefix "*" $respType }}
	if err := httputil.GetJSONBody(resp.Body, &out); err != nil {
		return {{ $errRet }}err
	}

	return &out, nil
            {{- else }}

	var out {{ $respType }}
	if err := httputil.GetJSONBody(resp.Body, &out); err != nil {
		return {{ $errRet }}err
	}

	return out, nil
            {{- end }}
        {{- else if eq $respType "io.Reader" }}

	return resp.Body, nil
        {{- else if eq $respType "[]byte" }}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return {{ $errRet }}fmt.Errorf("read response: %w", err)
	}

	return out, nil
        {{- else if hasPrefix "*" $respType }}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return {{ $errRet }}fmt.Errorf("read response: %w", err)
	}

	v := {{ trimPrefix "*" $respType }}(out)

	return &v, nil
        {{- else }}

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return {{ $errRet }}fmt.Errorf("read response: %w", err)
	}

	return {{ $respType }}(out), nil
        {{- end }}
}
    {{- end }}
{{- end }}
