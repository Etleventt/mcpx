package oauth

import (
	"bytes"
	"strings"
	"testing"
)

func TestSubDeskAuthorizationBrandPreservesProtocolFields(t *testing.T) {
	var output bytes.Buffer
	data := authorizePageData{ClientName: "Fixture", ClientID: "fixture-client", RedirectURI: "https://client.example/callback", CodeChallenge: "fixture-challenge", CodeChallengeMethod: "S256", State: "fixture-state", Resource: "https://hub.example/d/fixture/mcp", Scope: "mcp", FormAction: "/d/fixture/mcp/oauth/authorize"}
	if err := authorizePageTemplate.Execute(&output, data); err != nil {
		t.Fatal(err)
	}
	page := output.String()
	for _, value := range []string{"<title>授权访问 SubDesk</title>", "<h1>授权访问 SubDesk</h1>", "MCPX Runtime", "code_challenge", "fixture-challenge", "S256", "fixture-state", "/d/fixture/mcp/oauth/authorize", "设备访问口令", "并非端到端加密"} {
		if !strings.Contains(page, value) {
			t.Fatalf("authorization page lost %q", value)
		}
	}
	if strings.Contains(page, "授权访问 MCPX") {
		t.Fatal("old product name remained in authorization title")
	}
}
