package vhmaskd

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	libiptables "github.com/coreos/go-iptables/iptables"
	"github.com/google/shlex"
)

type IPTables struct {
	name        string
	servicePort int
	maskedPort  int
	iptables    *libiptables.IPTables
}

func NewIPTables(name string, servicePort int, maskedPort int) *IPTables {
	if !regexp.MustCompile("^[0-9a-zA-Z_]+$").MatchString(name) || len(name) > 28 {
		panic("Invalid iptables name: " + name)
	}
	ipt, err := libiptables.NewWithProtocol(libiptables.ProtocolIPv4)
	if err != nil {
		panic(err)
	}
	return &IPTables{
		name:        name,
		servicePort: servicePort,
		maskedPort:  maskedPort,
		iptables:    ipt,
	}
}

func (ipt *IPTables) Setup() error {
	sPort := strconv.Itoa(ipt.servicePort)
	mPort := strconv.Itoa(ipt.maskedPort)
	ipt.iptables.NewChain("nat", ipt.name)
	ipt.iptables.ClearChain("nat", ipt.name)
	ipt.iptables.AppendUnique(
		"nat", ipt.name,
		"-p", "tcp",
		"-j", "REDIRECT",
		"--to-port", sPort,
	)
	ipt.iptables.AppendUnique(
		"mangle", "PREROUTING",
		"-p", "tcp", "--dport", mPort,
		"-m", "state", "--state", "ESTABLISHED,RELATED",
		"-j", "ALLOW",
		"-m", "comment", "--comment", ipt.name+":related",
	)
	ipt.iptables.AppendUnique(
		"mangle", "PREROUTING",
		"-p", "tcp", "--dport", sPort,
		"-m", "mark", "!", "--mark", "777",
		"-j", "DROP",
		"-m", "comment", "--comment", ipt.name+":drop",
	)
	ipt.iptables.AppendUnique(
		"mangle", "PREROUTING",
		"-p", "tcp", "--dport", sPort,
		"-m", "mark", "!", "--mark", "777",
		"-j", "DROP",
		"-m", "comment", "--comment", ipt.name+":drop",
	)
	ipt.iptables.AppendUnique(
		"nat", "PREROUTING",
		"-p", "tcp", "--dport", mPort,
		"-j", ipt.name,
		"-m", "comment", "--comment", ipt.name+":entry",
	)
	ipt.iptables.AppendUnique(
		"mangle", "PREROUTING",
		"-p", "tcp", "--dport", mPort,
		"-j", "MARK", "--set-mark", "777",
		"-m", "comment", "--comment", ipt.name+":mark",
	)
	ipt.iptables.AppendUnique(
		"mangle", "PREROUTING",
		"-p", "tcp",
		"-m", "multiport", "--dports", sPort+","+mPort,
		"-j", "MARK", "--set-mark", "0",
		"-m", "comment", "--comment", ipt.name+":finish",
	)

	return nil
}

func iptablesSaveFormatRuleToRule(chain, rule string) []string {
	parts, err := shlex.Split(rule)
	if err != nil {
		panic(err)
	}
	if parts[0] != "-A" {
		panic("Invalid iptables rule (need -A): " + rule)
	}
	if parts[1] != chain {
		panic("Invalid iptables rule chain (need " + chain + "): " + rule)
	}
	return parts[2:]
}

func (ipt *IPTables) Teardown() error {
	ipt.iptables.ClearChain("nat", ipt.name)
	ipt.iptables.DeleteChain("nat", ipt.name)
	relatedRegexp := regexp.MustCompile("-m comment --comment \"" + ipt.name + ":[^\"]*\"$")
	// for table in nat, mangle
	var lasterr error
	for _, table := range []string{"nat", "mangle"} {
		rules, err := ipt.iptables.ListWithCounters(table, "PREROUTING")
		if err == nil {
			for _, rule := range rules {
				if relatedRegexp.MatchString(rule) {
					if err := ipt.iptables.Delete(table, "PREROUTING", iptablesSaveFormatRuleToRule("PREROUTING", rule)...); err != nil {
						lasterr = err
					}
				}
			}
		} else {
			lasterr = err
		}
	}
	return lasterr
}

func (ipt *IPTables) SyncAuthorizedIps(currentAuthorized []net.Addr) error {
	rules, err := ipt.iptables.List("nat", ipt.name)
	if err != nil {
		return err
	}
	ipExtractor := regexp.MustCompile(ipt.name + ":([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):")
	var hasRule map[net.Addr]bool = make(map[net.Addr]bool)
	var lastError error
	for _, rule := range rules {
		matches := ipExtractor.FindStringSubmatch(rule)
		if matches != nil {
			ip := matches[1]
			found := false
			for _, addr := range currentAuthorized {
				if addr.(*net.TCPAddr).IP.String() == ip {
					hasRule[addr] = true
					found = true
				}
			}
			if !found {
				if err := ipt.iptables.Delete("nat", ipt.name, iptablesSaveFormatRuleToRule(ipt.name, rule)...); err != nil {
					fmt.Printf("iptables delete: %s: %s\n", rule, err)
					lastError = err
				}
			}
		}
	}
	for _, addr := range currentAuthorized {
		if !hasRule[addr] {
			ip := addr.(*net.TCPAddr).IP.String()
			// FIXME: ignore the port for now
			err = ipt.iptables.Insert(
				"nat", ipt.name,
				1,
				"-p", "tcp",
				"-s", ip,
				"-j", "RETURN",
				"-m", "comment",
				"--comment", ipt.name+":"+addr.String()+": accept",
			)
			fmt.Println("iptables insert: ", addr.String(), err)
			if err != nil {
				lastError = err
			}
		}
	}
	return lastError
}
