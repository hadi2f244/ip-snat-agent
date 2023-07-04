/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	utiljson "encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"


	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/component-base/logs"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilexec "k8s.io/utils/exec"

	"github.com/golang/glog"
)

const (
	// path to a yaml or json file
	configPath = "/etc/config/ip-snat-agent"
)

var (
	// name of nat chain for iptables snat rules
	snatChain                         utiliptables.Chain
	snatChainFlag                     = flag.String("masq-chain", "SNAT-POSTROUTING", `Name of nat chain for iptables SNAT rules.`)
)


type SNATRule struct{
	Namespace string `yaml:"namespace"`
	SrcCIDR string `json:"srcCIDR"`
	DstCIDR string    `json:"dstCIDR"`
	SNATIp string  `json:"snatIp"`
}

type SNATConfig struct {
	SNATRules []SNATRule `json:"snatRules"`
	ResyncInterval     Duration `json:"resyncInterval"`
}

// Duration - Go's JSON unmarshaler can't handle time.ParseDuration syntax when unmarshaling into time.Duration, so we do it here
type Duration time.Duration

// UnmarshalJSON ...
func (d *Duration) UnmarshalJSON(json []byte) error {
	if json[0] == '"' {
		s := string(json[1 : len(json)-1])
		t, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(t)
		return nil
	}
	s := string(json)
	return fmt.Errorf("expected string value for unmarshal to field of type Duration, got %q", s)
}

func NewSNATRule() *SNATRule {
	return &SNATRule{
		Namespace: "default",
		SrcCIDR: "0.0.0.0/32",
		DstCIDR: "0.0.0.0/32",
		SNATIp: "0.0.0.0/32",
	}
}


// NewMasqConfig returns a SNATConfig with default values
func NewSNATConfig() *SNATConfig {
	return &SNATConfig{
		SNATRules: []SNATRule{},
		ResyncInterval:     Duration(60 * time.Second),
	}
}

// SNATDaemon object
type SNATDaemon struct {
	config    *SNATConfig
	iptables  utiliptables.Interface
}

// NewSNATDaemon returns a SNATDaemon with default values, including an initialized utiliptables.Interface
func NewSNATDaemon(c *SNATConfig) *SNATDaemon {
	execer := utilexec.New()
	protocolv4 := utiliptables.ProtocolIPv4
	iptables := utiliptables.New(execer, protocolv4)
	return &SNATDaemon{
		config:    c,
		iptables:  iptables,
	}
}

func main() {
	flag.Parse()

	version := "0.0.2"
	glog.Infof("ip-snat-agent version: %s", version)

	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		glog.Infof("FLAG: --%s=%q", f.Name, f.Value)
	})

	snatChain = utiliptables.Chain(*snatChainFlag)

	c := NewSNATConfig()

	logs.InitLogs()
	defer logs.FlushLogs()

	// verflag.PrintAndExitIfRequested()

	s := NewSNATDaemon(c)
	s.Run()
}

// Run ...
func (s *SNATDaemon) Run() {
	// Periodically resync to reconfigure or heal from any rule decay
	for {
		func() {
			defer time.Sleep(time.Duration(s.config.ResyncInterval))
			// resync config
			if err := s.osSyncConfig(); err != nil {
				glog.Errorf("error syncing configuration: %v", err)
				return
			}
			// resync rules
			if err := s.syncSNATRules(); err != nil {
				glog.Errorf("error syncing snat rules: %v", err)
				return
			}
		}()
	}
}

func (s *SNATDaemon) osSyncConfig() error {
	// the fakefs.FileSystem interface allows us to mock the fs from tests
	// fakefs.DefaultFS implements fakefs.FileSystem using os.Stat and io/ioutil.ReadFile
	var fs FileSystem = DefaultFS{}
	return s.syncConfig(fs)
}

// Syncs the config to the file at ConfigPath, or uses defaults if the file could not be found
// Error if the file is found but cannot be parsed.
func (s *SNATDaemon) syncConfig(fs FileSystem) error {
	var err error
	c := NewSNATConfig()
	defer func() {
		if err == nil {
			json, _ := utiljson.Marshal(c)
			glog.V(2).Infof("using config: %s", string(json))
		}
	}()

	// check if file exists
	if _, err = fs.Stat(configPath); os.IsNotExist(err) {
		// file does not exist, use defaults
		s.config.ResyncInterval = c.ResyncInterval
		s.config.SNATRules = append(s.config.SNATRules, c.SNATRules...)
		glog.V(2).Infof("no config file found at %q, using default values", configPath)
		return nil
	}
	glog.V(2).Infof("config file found at %q", configPath)

	// file exists, read and parse file
	yaml, err := fs.ReadFile(configPath)
	if err != nil {
		return err
	}

	json, err := utilyaml.ToJSON(yaml)
	if err != nil {
		return err
	}

	// Only overwrites fields provided in JSON
	if err = utiljson.Unmarshal(json, c); err != nil {
		return err
	}

	// validate configuration
	if err := c.validate(); err != nil {
		return err
	}

	// apply new config
	s.config = c
	return nil
}

func (c *SNATConfig) validate() error {
	// // limit to 64 CIDRs (excluding link-local) to protect against really bad mistakes
	// n := len(c.NonMasqueradeCIDRs)
	// l := c.CidrLimit

	// if n > l {
	// 	return fmt.Errorf("the daemon can only accept up to %d CIDRs (excluding link-local), but got %d CIDRs (excluding link local)", l, n)
	// }
	// // check CIDRs are valid
	// for _, cidr := range c.NonMasqueradeCIDRs {
	// 	if err := validateCIDR(cidr); err != nil {
	// 		return err
	// 	}
	// 	// can't configure ipv6 cidr if ipv6 is not enabled
	// 	if !*enableIPv6 && isIPv6CIDR(cidr) {
	// 		return fmt.Errorf("ipv6 is not enabled, but ipv6 cidr %s provided. Enable ipv6 using --enable-ipv6 agent flag", cidr)
	// 	}
	// }
	return nil
}

const cidrParseErrFmt = "CIDR %q could not be parsed, %v"
const cidrAlignErrFmt = "CIDR %q is not aligned to a CIDR block, ip: %q network: %q"

func validateCIDR(cidr string) error {
	// parse test
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf(cidrParseErrFmt, cidr, err)
	}
	// alignment test
	if !ip.Equal(ipnet.IP) {
		return fmt.Errorf(cidrAlignErrFmt, cidr, ip, ipnet.String())
	}
	return nil
}

func (s *SNATDaemon) syncSNATRules() error {
	// make sure our custom chain for non-masquerade exists
	s.iptables.EnsureChain(utiliptables.TableNAT, snatChain)

	// ensure that any non-local in POSTROUTING jumps to masqChain
	if err := s.ensurePostroutingJump(); err != nil {
		return err
	}

	// build up lines to pass to iptables-restore
	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*nat")
	writeLine(lines, utiliptables.MakeChainLine(snatChain)) // effectively flushes masqChain atomically with rule restore

	// SNAT all other traffic
	for _,snatRule := range s.config.SNATRules {
		writeSNATRule(lines, snatRule.Namespace, snatRule.SrcCIDR, snatRule.DstCIDR, snatRule.SNATIp)
	}

	writeLine(lines, "COMMIT")

	if err := s.iptables.RestoreAll(lines.Bytes(), utiliptables.NoFlushTables, utiliptables.NoRestoreCounters); err != nil {
		return err
	}
	return nil
}

// NOTE(mtaufen): iptables requires names to be <= 28 characters, and somehow prepending "-m comment --comment " to this string makes it think this condition is violated
// Feel free to dig around in iptables and see if you can figure out exactly why; I haven't had time to fully trace how it parses and handle subcommands.
// If you want to investigate, get the source via `git clone git://git.netfilter.org/iptables.git`, `git checkout v1.4.21` (the version I've seen this issue on,
// though it may also happen on others), and start with `git grep XT_EXTENSION_MAXNAMELEN`.
const postRoutingMasqChainCommentFormat = "\"ip-snat-agent: ensure nat POSTROUTING directs all non-LOCAL destination traffic to our custom %s chain\""

func postroutingJumpComment() string {
	return fmt.Sprintf(postRoutingMasqChainCommentFormat, snatChain)
}

func (m *SNATDaemon) ensurePostroutingJump() error {
	if _, err := m.iptables.EnsureRule(utiliptables.Append, utiliptables.TableNAT, utiliptables.ChainPostrouting,
		"-m", "comment", "--comment", postroutingJumpComment(),
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(snatChain)); err != nil {
		return fmt.Errorf("failed to ensure that %s chain %s jumps to SNAT: %v", utiliptables.TableNAT, snatChain, err)
	}
	return nil
}

const snatRuleCommentTemplate = `-m comment --comment "ip-snat-agent: outbound traffic is subject to SNAT (kubernetes namespace: %s)"`

func writeSNATRule(lines *bytes.Buffer, namespace string, srcCIDR string, dstCIDR string, SNATIp string) {
	snatRuleComment := fmt.Sprintf(snatRuleCommentTemplate, namespace)
	writeRule(lines, utiliptables.Append, snatChain, snatRuleComment, "-s",srcCIDR, "-d", dstCIDR, "-j", "SNAT", "--to", SNATIp)
}

// Similar syntax to utiliptables.Interface.EnsureRule, except you don't pass a table
// (you must write these rules under the line with the table name)
func writeRule(lines *bytes.Buffer, position utiliptables.RulePosition, chain utiliptables.Chain, args ...string) {
	fullArgs := append([]string{string(position), string(chain)}, args...)
	writeLine(lines, fullArgs...)
}

// Join all words with spaces, terminate with newline and write to buf.
func writeLine(lines *bytes.Buffer, words ...string) {
	lines.WriteString(strings.Join(words, " ") + "\n")
}