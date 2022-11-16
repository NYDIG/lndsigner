package main

import (
	"os"

	"github.com/bottlepay/lndsigner/vault"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	logger := hclog.New(&hclog.LoggerOptions{})

	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: vault.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             logger,
	})
	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
