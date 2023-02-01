// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package lndsigner

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bottlepay/lndsigner/vault"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	flags "github.com/jessevdk/go-flags"
)

const (
	defaultConfigFilename  = "signer.conf"
	defaultTLSCertFilename = "tls.cert"
	defaultTLSKeyFilename  = "tls.key"
	defaultRPCPort         = 10009
	defaultRPCHost         = "localhost"
)

var (
	// DefaultSignerDir is the default directory where lndsignerd tries to
	// find its configuration file and store its data. This is a directory
	// in the user's application data, for example:
	//   C:\Users\<username>\AppData\Local\Lndsigner on Windows
	//   ~/.lndsigner on Linux
	//   ~/Library/Application Support/Lndsigner on MacOS
	DefaultSignerDir = btcutil.AppDataDir("lndsigner", false)

	// DefaultConfigFile is the default full path of lndsignerd's
	// configuration file.
	DefaultConfigFile = filepath.Join(DefaultSignerDir, defaultConfigFilename)

	defaultTLSCertPath = filepath.Join(DefaultSignerDir, defaultTLSCertFilename)
	defaultTLSKeyPath  = filepath.Join(DefaultSignerDir, defaultTLSKeyFilename)
)

// Config defines the configuration options for lndsignerd.
//
// See LoadConfig for further details regarding the configuration
// loading+parsing process.
type Config struct {
	SignerDir  string `long:"signerdir" description:"The base directory that contains signer's data, logs, configuration file, etc."`
	ConfigFile string `short:"C" long:"configfile" description:"Path to configuration file"`

	TLSCertPath string `long:"tlscertpath" description:"Path to write the TLS certificate for lndsignerd's RPC services"`
	TLSKeyPath  string `long:"tlskeypath" description:"Path to write the TLS private key for lndsignerd's RPC services"`

	// We'll parse these 'raw' string arguments into real net.Addrs in the
	// loadConfig function. We need to expose the 'raw' strings so the
	// command line library can access them.
	// Only the parsed net.Addrs should be used!
	RawRPCListeners []string `long:"rpclisten" description:"Add an interface/port/socket to listen for RPC connections"`
	RPCListeners    []net.Addr

	Network string `long:"network" description:"The network for which the node was created in the vault. One of: 'testnet', 'simnet', 'regtest', 'signet'"`

	// ActiveNetParams contains parameters of the target chain.
	ActiveNetParams chaincfg.Params

	// Node contains the node ID as a 66-character hex string.
	NodePubKey string `long:"nodepubkey" description:"Node pubkey hex"`
}

// DefaultConfig returns all default values for the Config struct.
func DefaultConfig() Config {
	return Config{
		SignerDir:   DefaultSignerDir,
		ConfigFile:  DefaultConfigFile,
		TLSCertPath: defaultTLSCertPath,
		TLSKeyPath:  defaultTLSKeyPath,
		Network:     "regtest",
	}
}

// LoadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
//  1. Start with a default config with sane settings
//  2. Pre-parse the command line to check for an alternative config file
//  3. Load configuration file overwriting defaults with any specified options
//  4. Parse CLI options and overwrite/add any specified options
func LoadConfig() (*Config, error) {
	// Pre-parse the command line options to pick up an alternative config
	// file.
	preCfg := DefaultConfig()
	if _, err := flags.Parse(&preCfg); err != nil {
		return nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)

	// If the config file path has not been modified by the user, then we'll
	// use the default config file path. However, if the user has modified
	// their signerdir, then we should assume they intend to use the config
	// file within it.
	configFileDir := CleanAndExpandPath(preCfg.SignerDir)
	configFilePath := CleanAndExpandPath(preCfg.ConfigFile)
	switch {
	// User specified --signerdir but no --configfile. Update the config
	// file path to the lndsignerd config directory, but don't require it
	// to exist.
	case configFileDir != DefaultSignerDir &&
		configFilePath == DefaultConfigFile:

		configFilePath = filepath.Join(
			configFileDir, defaultConfigFilename,
		)

	// User did specify an explicit --configfile, so we check that it does
	// exist under that path to avoid surprises.
	case configFilePath != DefaultConfigFile:
		if !fileExists(configFilePath) {
			return nil, fmt.Errorf("specified config file does "+
				"not exist in %s", configFilePath)
		}
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := preCfg
	fileParser := flags.NewParser(&cfg, flags.Default)
	err := flags.NewIniParser(fileParser).ParseFile(configFilePath)
	if err != nil {
		// If it's a parsing related error, then we'll return
		// immediately, otherwise we can proceed as possibly the config
		// file doesn't exist which is OK.
		if _, ok := err.(*flags.IniError); ok {
			return nil, err
		}

		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	flagParser := flags.NewParser(&cfg, flags.Default)
	if _, err := flagParser.Parse(); err != nil {
		return nil, err
	}

	// Make sure everything we just loaded makes sense.
	cleanCfg, err := ValidateConfig(
		cfg, fileParser, flagParser,
	)
	if usageErr, ok := err.(*usageError); ok {
		// The logging system might not yet be initialized, so we also
		// write to stderr to make sure the error appears somewhere.
		_, _ = fmt.Fprintln(os.Stderr, usageMessage)
		signerLog.Warnf("Incorrect usage: %v", usageMessage)

		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		signerLog.Warnf("Error validating config: %v", usageErr.err)

		return nil, usageErr.err
	}
	if err != nil {
		// The log subsystem might not yet be initialized. But we still
		// try to log the error there since some packaging solutions
		// might only look at the log and not stdout/stderr.
		signerLog.Warnf("Error validating config: %v", err)

		return nil, err
	}

	// Warn about missing config file only after all other configuration is
	// done. This prevents the warning on help messages and invalid options.
	// Note this should go directly before the return.
	if configFileError != nil {
		signerLog.Warnf("%v", configFileError)
	}

	return cleanCfg, nil
}

// usageError is an error type that signals a problem with the supplied flags.
type usageError struct {
	err error
}

// Error returns the error string.
//
// NOTE: This is part of the error interface.
func (u *usageError) Error() string {
	return u.err.Error()
}

// ValidateConfig check the given configuration to be sane. This makes sure no
// illegal values or combination of values are set. All file system paths are
// normalized. The cleaned up config is returned on success.
func ValidateConfig(cfg Config, fileParser, flagParser *flags.Parser) (
	*Config, error) {

	// If the provided lndsignerd directory is not the default, we'll
	// modify the path to all of the files and directories that will live
	// within it.
	signerDir := CleanAndExpandPath(cfg.SignerDir)
	if signerDir != DefaultSignerDir {
		cfg.TLSCertPath = filepath.Join(signerDir, defaultTLSCertFilename)
		cfg.TLSKeyPath = filepath.Join(signerDir, defaultTLSKeyFilename)
	}

	funcName := "ValidateConfig"
	mkErr := func(format string, args ...interface{}) error {
		return fmt.Errorf(funcName+": "+format, args...)
	}
	makeDirectory := func(dir string) error {
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			// Show a nicer error message if it's because a symlink
			// is linked to a directory that does not exist
			// (probably because it's not mounted).
			if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
				link, lerr := os.Readlink(e.Path)
				if lerr == nil {
					str := "is symlink %s -> %s mounted?"
					err = fmt.Errorf(str, e.Path, link)
				}
			}

			str := "Failed to create lndsigner directory '%s': %v"
			return mkErr(str, dir, err)
		}

		return nil
	}

	// As soon as we're done parsing configuration options, ensure all paths
	// to directories and files are cleaned and expanded before attempting
	// to use them later on.
	cfg.TLSCertPath = CleanAndExpandPath(cfg.TLSCertPath)
	cfg.TLSKeyPath = CleanAndExpandPath(cfg.TLSKeyPath)

	params, err := vault.GetNet(cfg.Network)
	if err != nil {
		return nil, err
	}
	cfg.ActiveNetParams = *params

	// Create the lndsignerd directory and all other sub-directories if
	// they don't already exist. This makes sure that directory trees are
	// also created for files that point to outside the signerdir.
	dirs := []string{
		signerDir, filepath.Dir(cfg.TLSCertPath),
		filepath.Dir(cfg.TLSKeyPath),
	}
	for _, dir := range dirs {
		if err := makeDirectory(dir); err != nil {
			return nil, err
		}
	}

	// At least one RPCListener is required. So listen on localhost per
	// default.
	if len(cfg.RawRPCListeners) == 0 {
		addr := fmt.Sprintf("localhost:%d", defaultRPCPort)
		cfg.RawRPCListeners = append(cfg.RawRPCListeners, addr)
	}

	// Add default port to all RPC listener addresses if needed and remove
	// duplicate addresses.
	cfg.RPCListeners, err = NormalizeAddresses(
		cfg.RawRPCListeners, strconv.Itoa(defaultRPCPort))
	if err != nil {
		return nil, mkErr("error normalizing RPC listen addrs: %v", err)
	}

	// All good, return the sanitized result.
	return &cfg, nil
}

// CleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func CleanAndExpandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		var homeDir string
		u, err := user.Current()
		if err == nil {
			homeDir = u.HomeDir
		} else {
			homeDir = os.Getenv("HOME")
		}

		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// NormalizeAddresses returns a new slice with all the passed addresses
// normalized with the given default port and all duplicates removed.
func NormalizeAddresses(addrs []string, defaultPort string) ([]net.Addr,
	error) {

	result := make([]net.Addr, 0, len(addrs))
	seen := map[string]struct{}{}

	for _, addr := range addrs {
		parsedAddr, err := ParseAddressString(addr, defaultPort)
		if err != nil {
			return nil, fmt.Errorf("parse address %s failed: %w",
				addr, err)
		}

		if _, ok := seen[parsedAddr.String()]; !ok {
			result = append(result, parsedAddr)
			seen[parsedAddr.String()] = struct{}{}
		}
	}

	return result, nil
}

// verifyPort makes sure that an address string has both a host and a port. If
// there is no port found, the default port is appended. If the address is just
// a port, then we'll assume that the user is using the short cut to specify a
// localhost:port address.
func verifyPort(address string, defaultPort string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// If the address itself is just an integer, then we'll assume
		// that we're mapping this directly to a localhost:port pair.
		// This ensures we maintain the legacy behavior.
		if _, err := strconv.Atoi(address); err == nil {
			return net.JoinHostPort("localhost", address)
		}

		// Otherwise, we'll assume that the address just failed to
		// attach its own port, so we'll use the default port. In the
		// case of IPv6 addresses, if the host is already surrounded by
		// brackets, then we'll avoid using the JoinHostPort function,
		// since it will always add a pair of brackets.
		if strings.HasPrefix(address, "[") {
			return address + ":" + defaultPort
		}
		return net.JoinHostPort(address, defaultPort)
	}

	// In the case that both the host and port are empty, we'll use the
	// default port.
	if host == "" && port == "" {
		return ":" + defaultPort
	}

	return address
}

// ParseAddressString converts an address in string format to a net.Addr that is
// compatible with lndsignerd.
func ParseAddressString(strAddress string, defaultPort string) (net.Addr,
	error) {

	var parsedNetwork, parsedAddr string

	// Addresses can either be in network://address:port format,
	// network:address:port, address:port, or just port. We want to support
	// all possible types.
	if strings.Contains(strAddress, "://") {
		parts := strings.Split(strAddress, "://")
		parsedNetwork, parsedAddr = parts[0], parts[1]
	} else if strings.Contains(strAddress, ":") {
		parts := strings.Split(strAddress, ":")
		parsedNetwork = parts[0]
		parsedAddr = strings.Join(parts[1:], ":")
	}

	// Only TCP and Unix socket addresses are valid. We can't use IP or
	// UDP only connections for anything we do here.
	switch parsedNetwork {
	case "unix", "unixpacket":
		return net.ResolveUnixAddr(parsedNetwork, parsedAddr)

	case "", "tcp", "tcp4", "tcp6":
		return net.ResolveTCPAddr(
			parsedNetwork, verifyPort(parsedAddr, defaultPort),
		)

	default:
		return nil, fmt.Errorf("only TCP or unix socket "+
			"addresses are supported: %s", parsedAddr)
	}
}
