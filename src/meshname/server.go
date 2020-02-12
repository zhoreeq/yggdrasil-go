package meshname

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gologme/log"
	"github.com/miekg/dns"

	"github.com/yggdrasil-network/yggdrasil-go/src/admin"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/yggdrasil"
)

const DomainZone = "meshname."

func DomainFromIP(target net.IP) string {
	return strings.ToLower(base32.StdEncoding.EncodeToString(target)[0:26])
}

func IPFromDomain(domain string) (net.IP, error) {
	name := strings.ToUpper(domain) + "======"
	data, err := base32.StdEncoding.DecodeString(name)
	if err != nil {
		return net.IP{}, err
	}
	if len(data) != 16 {
		return net.IP{}, errors.New("Invalid subdomain")
	}
	ipAddr := net.IP(data)
	if ipAddr == nil {
		return net.IP{}, errors.New("Invalid IP address")
	}
	return ipAddr, nil
}

func GenConf(target string) (string, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		return "", errors.New("Invalid IP address")
	}
	zone := DomainFromIP(ip)
	selfRecord := fmt.Sprintf("\t\t\"%s.%s AAAA %s\"\n", zone, DomainZone, target)
	confString := fmt.Sprintf("{\n\t\"%s\":[\n%s\t]\n}", zone, selfRecord)

	return confString, nil
}

type MeshnameServer struct {
	core        *yggdrasil.Core
	config      *config.NodeState
	validSubnet *net.IPNet
	log         *log.Logger
	zoneConfig  map[string][]dns.RR
	dnsClient   *dns.Client
	dnsServer   *dns.Server
	started     bool
}

func (s *MeshnameServer) Init(core *yggdrasil.Core, config *config.NodeState, log *log.Logger, options interface{}) error {
	s.core = core
	s.config = config
	s.log = log
	s.started = false
	s.validSubnet = &net.IPNet{net.ParseIP("200::"), net.CIDRMask(7, 128)}
	s.zoneConfig = make(map[string][]dns.RR)
	if s.dnsClient == nil {
		s.dnsClient = new(dns.Client)
		s.dnsClient.Timeout = 5000000000 // increased 5 seconds timeout
	}
	return nil
}

func (s *MeshnameServer) LoadConfig(current config.NodeConfig) {
	for k := range s.zoneConfig {
		delete(s.zoneConfig, k)
	}

	for k, items := range current.DNSServer.Config {
		for _, item := range items {
			rr, err := dns.NewRR(item)
			if err != nil {
				s.log.Warnln("Invalid DNS record:", item)
				continue
			}
			s.zoneConfig[k] = append(s.zoneConfig[k], rr)
		}
	}

	s.log.Debugln("Meshname config loaded")
}

func (s *MeshnameServer) Stop() error {
	if s.started {
		s.dnsServer.Shutdown()
		s.started = false
	}
	return nil
}

func (s *MeshnameServer) Start() error {
	current := s.config.GetCurrent()
	if current.DNSServer.Enable == false {
		return nil
	}
	s.LoadConfig(current)
	s.dnsServer = &dns.Server{Addr: current.DNSServer.Listen, Net: "udp"}
	dns.HandleFunc(DomainZone, s.handleRequest)
	s.started = true
	go s.dnsServer.ListenAndServe()
	s.log.Debugln("Started meshnamed on:", current.DNSServer.Listen)
	return nil
}

func (s *MeshnameServer) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	var remoteLookups = make(map[string][]dns.Question)
	m := new(dns.Msg)
	m.SetReply(r)

	for _, q := range r.Question {
		labels := dns.SplitDomainName(q.Name)
		if len(labels) < 2 {
			s.log.Debugln("Error: invalid domain requested")

			continue
		}
		subDomain := labels[len(labels)-2]

		resolvedAddr, err := IPFromDomain(subDomain)
		if err != nil {
			s.log.Debugln(err)
			continue
		}
		if !s.validSubnet.Contains(resolvedAddr) {
			s.log.Debugln("Error: subnet doesn't match")
			continue
		}
		if records, ok := s.zoneConfig[subDomain]; ok {
			for _, rec := range records {
				if h := rec.Header(); h.Name == q.Name && h.Rrtype == q.Qtype && h.Class == q.Qclass {
					m.Answer = append(m.Answer, rec)
				}
			}
		} else if ra := w.RemoteAddr().String(); strings.HasPrefix(ra, "[::1]:") || strings.HasPrefix(ra, "127.0.0.1:") {
			// TODO prefix whitelists ?
			// do remote lookups only for local clients
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

func (s *MeshnameServer) IsStarted() bool {
	return s.started
}

func (s *MeshnameServer) UpdateConfig(config *config.NodeConfig) {
	s.Stop()
	s.config.Replace(*config)
	s.Start()
}

func (s *MeshnameServer) SetupAdminHandlers(a *admin.AdminSocket) {}
