package nameserver

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gologme/log"
	"github.com/miekg/dns"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/admin"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"
	"github.com/yggdrasil-network/yggdrasil-go/src/yggdrasil"
)

const DomainZone = "leaf."

func IPFromDomain(domain *string) (net.IP, error) {
	name := strings.ToUpper(*domain) + "===="
	pubkey, err := base32.StdEncoding.DecodeString(name)
	if err != nil {
		return net.IP{}, err
	}
	if len(pubkey) != 32 {
		return net.IP{}, errors.New("Invalid subdomain")
	}

	var box crypto.BoxPubKey
	copy(box[:], pubkey[:])
	nodeid := crypto.GetNodeID(&box)
	if nodeid == nil {
		return net.IP{}, errors.New("Invalid nodeid")
	}
	addr := *address.AddrForNodeID(nodeid)
	ipAddr := net.IP(addr[:])

	return ipAddr, nil
}

func DomainFromPubKey(pubkey string) (string, error) {
	data, err := hex.DecodeString(pubkey)
	if err != nil {
		return "", err
	}
	return strings.ToLower(base32.StdEncoding.EncodeToString(data)[0:52]), nil
}

func GenConf(pubkey string) (string, error) {
	domain, _ := DomainFromPubKey(pubkey)
	ip, _ := IPFromDomain(&domain)
	selfRecord := fmt.Sprintf("[\"%s.%s AAAA %s\"]\n", domain, DomainZone, ip)
	return selfRecord, nil
}

type NameServer struct {
	core       *yggdrasil.Core
	config     *config.NodeState
	log        *log.Logger
	subdomain  string
	zoneConfig []dns.RR
	dnsClient  *dns.Client
	dnsServer  *dns.Server
	started    bool
}

func (s *NameServer) Init(core *yggdrasil.Core, config *config.NodeState, log *log.Logger, options interface{}) error {
	s.core = core
	s.config = config
	s.log = log
	s.started = false
	if s.dnsClient == nil {
		s.dnsClient = new(dns.Client)
		s.dnsClient.Timeout = 5000000000 // increased 5 seconds timeout
	}
	return nil
}

func (s *NameServer) LoadConfig(current config.NodeConfig) {
	subdomain, _ := DomainFromPubKey(current.EncryptionPublicKey)
	s.subdomain = subdomain
	s.zoneConfig = nil

	for _, item := range current.NameServer.Config {
		rr, err := dns.NewRR(item)
		if err != nil {
			s.log.Warnln("Invalid DNS record:", item)
			continue
		}
		s.zoneConfig = append(s.zoneConfig, rr)
	}

	s.log.Debugln("NameServer config loaded")
}

func (s *NameServer) Stop() error {
	if s.started {
		s.dnsServer.Shutdown()
		s.started = false
	}
	return nil
}

func (s *NameServer) Start() error {
	current := s.config.GetCurrent()
	if current.NameServer.Enable == false {
		return nil
	}
	s.LoadConfig(current)
	s.dnsServer = &dns.Server{Addr: current.NameServer.Listen, Net: "udp"}
	dns.HandleFunc(DomainZone, s.handleRequest)
	s.started = true
	go s.dnsServer.ListenAndServe()
	s.log.Debugln("Started NameServer on:", current.NameServer.Listen)
	return nil
}

func (s *NameServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	var remoteLookups = make(map[string][]dns.Question)
	m := new(dns.Msg)
	m.SetReply(r)

	for _, q := range r.Question {
		labels := dns.SplitDomainName(q.Name)
		if len(labels) < 2 {
			s.log.Debugln("Error: invalid domain requested")
			continue
		}
		subdomain := labels[len(labels)-2]

		if subdomain == s.subdomain {
			for _, rec := range s.zoneConfig {
				if h := rec.Header(); h.Name == q.Name && h.Rrtype == q.Qtype && h.Class == q.Qclass {
					m.Answer = append(m.Answer, rec)
				}
			}
		} else if s.isRemoteLookupAllowed(w.RemoteAddr()) {
			resolvedAddr, err := IPFromDomain(&subdomain) // TODO add cache
			if err != nil {
				s.log.Debugln(err)
				continue
			}
			remoteLookups[resolvedAddr.String()] = append(remoteLookups[resolvedAddr.String()], q)
		}
	}

	for remoteServer, questions := range remoteLookups {
		rm := new(dns.Msg)
		rm.Question = questions
		resp, _, err := s.dnsClient.Exchange(rm, "["+remoteServer+"]:53") // no retries
		if err != nil {
			s.log.Debugln(err)
			continue
		}
		m.Answer = append(m.Answer, resp.Answer...)
	}
	w.WriteMsg(m)
}

func (s *NameServer) isRemoteLookupAllowed(addr net.Addr) bool {
	// TODO prefix whitelists ?
	ra := addr.String()
	return strings.HasPrefix(ra, "[::1]:") || strings.HasPrefix(ra, "127.0.0.1:")
}

func (s *NameServer) IsStarted() bool {
	return s.started
}

func (s *NameServer) UpdateConfig(config *config.NodeConfig) {
	s.Stop()
	s.config.Replace(*config)
	s.Start()
}

func (s *NameServer) SetupAdminHandlers(a *admin.AdminSocket) {}
