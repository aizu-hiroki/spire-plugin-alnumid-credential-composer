package main

import (
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func main() {
	plugin := new(Plugin)
	pluginmain.Serve(
		credentialcomposerv1.CredentialComposerPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
