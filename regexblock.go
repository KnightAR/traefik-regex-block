package traefik_regex_block

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config defines the configuration options for the plugin.
type Config struct {
	RegexPatterns        []string `json:"regexPatterns,omitempty"`
	BlockDurationMinutes int      `json:"blockDurationMinutes,omitempty"`
	Whitelist            []string `json:"whitelist,omitempty"`
	EnableDebug          bool     `json:"enableDebug,omitempty"`

	// MaxBlockedIPs limits the number of blocked IPs kept in memory.
	// Zero or unset means unlimited.
	MaxBlockedIPs int `json:"maxBlockedIPs,omitempty"`

	// MaxViolationIPs limits the number of pre-block violation IPs kept in memory.
	// Zero or unset means unlimited, unless MaxBlockedIPs is set. When MaxBlockedIPs
	// is set and MaxViolationIPs is unset, MaxViolationIPs defaults to MaxBlockedIPs.
	MaxViolationIPs int `json:"maxViolationIPs,omitempty"`

	// ViolationsBeforeBlock controls how many regex matches are required before blocking.
	// Zero or unset means 1, which preserves the original immediate-block behavior.
	ViolationsBeforeBlock int `json:"violationsBeforeBlock,omitempty"`

	// ViolationWindowSeconds controls the rolling window for violation counting.
	// Only used when ViolationsBeforeBlock > 1. Zero or unset means 300 seconds.
	ViolationWindowSeconds int `json:"violationWindowSeconds,omitempty"`

	// ClientIPHeader is the HTTP header to trust when the immediate peer is trusted.
	// Default: CF-Connecting-IP
	ClientIPHeader string `json:"clientIPHeader,omitempty"`

	// TrustedProxyCIDRs is an optional list of trusted proxy CIDRs.
	// If set, only these CIDRs are trusted and Cloudflare auto-fetch is skipped.
	// If empty, Cloudflare IP ranges are lazily fetched when CF-Connecting-IP is present.
	TrustedProxyCIDRs []string `json:"trustedProxyCIDRs,omitempty"`
}

// CreateConfig creates a default configuration for the plugin.
func CreateConfig() *Config {
	return &Config{
		BlockDurationMinutes: 60, // Default block duration: 1 hour
		EnableDebug:          false,
		ClientIPHeader:       "CF-Connecting-IP",
		MaxBlockedIPs:        0,   // Unlimited by default
		MaxViolationIPs:      0,   // Unlimited by default, unless maxBlockedIPs is set
		ViolationsBeforeBlock: 1,  // Preserve original immediate-block behavior
		ViolationWindowSeconds: 300, // 5 minutes
	}
}

// RegexBlock is a Traefik plugin that blocks requests matching certain regex patterns.
type RegexBlock struct {
	next          http.Handler
	name          string
	regexPatterns []*regexp.Regexp
	blockDuration int
	whitelist     []*net.IPNet
	blockedIPs    map[string]time.Time
	logger        *pluginLogger
	blockMgr      *BlockManager
	violationMgr  *ViolationManager
	mutex         sync.Mutex

	maxBlockedIPs          int
	maxViolationIPs        int
	violationsBeforeBlock  int
	violationWindowSeconds int

	clientIPHeader    string
	trustedProxyCIDRs []string
	trustedProxyNets  []*net.IPNet

	cfFetchMu       sync.RWMutex
	cfFetchedAt     time.Time
	cfCacheTTL      time.Duration
	cfFetchInFlight bool
}

// New creates a new instance of the RegexBlock.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logLevel := "info"
	if config.EnableDebug {
		logLevel = "debug"
	}

	logger := newPluginLogger(logLevel, name)
	logger.Info("RegexBlock plugin is starting.")

	// Setup list of regex patterns.
	regexPatterns := make([]*regexp.Regexp, 0)
	for _, pattern := range config.RegexPatterns {
		compiledRegex, err := regexp.Compile(pattern)
		if err != nil {
			logger.Error(fmt.Sprintf("Regex pattern %s is invalid and will not be used.", pattern))
			continue
		}

		regexPatterns = append(regexPatterns, compiledRegex)
		logger.Debug(fmt.Sprintf("Adding regex pattern %s", compiledRegex.String()))
	}

	if len(regexPatterns) == 0 {
		logger.Error("There were no valid regex patterns. Plugin will not load.")
		return nil, errors.New("No valid regex patterns found.")
	}

	// Setup block duration.
	blockDuration := config.BlockDurationMinutes
	if blockDuration <= 0 {
		blockDuration = 60
		logger.Debug("Block duration was not set or was invalid. Falling back to 60 minutes.")
	}
	logger.Info(fmt.Sprintf("Setting block duration as %d minutes.", blockDuration))

	maxBlockedIPs := config.MaxBlockedIPs
	if maxBlockedIPs < 0 {
		maxBlockedIPs = 0
		logger.Debug("Max blocked IPs was negative. Falling back to unlimited.")
	}
	if maxBlockedIPs == 0 {
		logger.Info("Max blocked IPs is unlimited.")
	} else {
		logger.Info(fmt.Sprintf("Setting max blocked IPs as %d.", maxBlockedIPs))
	}

	maxViolationIPs := config.MaxViolationIPs
	if maxViolationIPs < 0 {
		maxViolationIPs = 0
		logger.Debug("Max violation IPs was negative. Falling back to unlimited.")
	}
	if maxViolationIPs == 0 && maxBlockedIPs > 0 {
		maxViolationIPs = maxBlockedIPs
		logger.Debug(fmt.Sprintf("Max violation IPs was not set. Falling back to max blocked IPs value of %d.", maxViolationIPs))
	}
	if maxViolationIPs == 0 {
		logger.Info("Max violation IPs is unlimited.")
	} else {
		logger.Info(fmt.Sprintf("Setting max violation IPs as %d.", maxViolationIPs))
	}

	violationsBeforeBlock := config.ViolationsBeforeBlock
	if violationsBeforeBlock <= 0 {
		violationsBeforeBlock = 1
		logger.Debug("Violations before block was not set or invalid. Falling back to 1.")
	}
	logger.Info(fmt.Sprintf("Setting violations before block as %d.", violationsBeforeBlock))

	violationWindowSeconds := config.ViolationWindowSeconds
	if violationWindowSeconds <= 0 {
		violationWindowSeconds = 300
		logger.Debug("Violation window seconds was not set or invalid. Falling back to 300 seconds.")
	}
	logger.Info(fmt.Sprintf("Setting violation window as %d seconds.", violationWindowSeconds))

	// Setup list of IP addresses to whitelist.
	whitelist := make([]*net.IPNet, 0)
	for _, ip := range config.Whitelist {
		ipNet := parseIPOrCIDR(ip)
		if ipNet == nil {
			logger.Error(fmt.Sprintf("Whitelist IP address %s is invalid and will not be used.", ip))
			continue
		}

		whitelist = append(whitelist, ipNet)
		logger.Debug(fmt.Sprintf("Adding whitelist IP %s", ip))
	}

	clientIPHeader := config.ClientIPHeader
	if clientIPHeader == "" {
		clientIPHeader = "CF-Connecting-IP"
		logger.Debug("Client IP header was not set. Falling back to CF-Connecting-IP.")
	}
	logger.Info(fmt.Sprintf("Using client IP header %s when trusted proxy validation passes.", clientIPHeader))

	// Setup list of trusted proxy CIDRs.
	// If this list is empty, Cloudflare CIDRs are lazily fetched on the first request
	// with CF-Connecting-IP present.
	trustedProxyNets := make([]*net.IPNet, 0)
	for _, cidr := range config.TrustedProxyCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logger.Error(fmt.Sprintf("Trusted proxy CIDR %s is invalid and will not be used.", cidr))
			continue
		}

		trustedProxyNets = append(trustedProxyNets, ipNet)
		logger.Debug(fmt.Sprintf("Adding trusted proxy CIDR %s", cidr))
	}

	if len(config.TrustedProxyCIDRs) > 0 {
		logger.Info(fmt.Sprintf("Loaded %d configured trusted proxy CIDR(s). Cloudflare auto-fetch is disabled.", len(trustedProxyNets)))
	} else {
		logger.Info("No trusted proxy CIDRs configured. Cloudflare CIDRs will be lazily fetched when CF-Connecting-IP is present.")
	}

	// Setup managers. Currently only supports in-memory storage.
	// Future plans to support Redis and/or MySQL.
	blockMgr := ArrayBlockManager(maxBlockedIPs)
	violationMgr := ArrayViolationManager(maxViolationIPs)

	return &RegexBlock{
		next:                   next,
		name:                   name,
		regexPatterns:          regexPatterns,
		blockDuration:          blockDuration,
		whitelist:              whitelist,
		blockedIPs:             make(map[string]time.Time),
		logger:                 logger,
		blockMgr:               blockMgr,
		violationMgr:           violationMgr,
		maxBlockedIPs:          maxBlockedIPs,
		maxViolationIPs:        maxViolationIPs,
		violationsBeforeBlock:  violationsBeforeBlock,
		violationWindowSeconds: violationWindowSeconds,
		clientIPHeader:         clientIPHeader,
		trustedProxyCIDRs:      config.TrustedProxyCIDRs,
		trustedProxyNets:       trustedProxyNets,
		cfCacheTTL:             24 * time.Hour,
	}, nil
}

// ServeHTTP intercepts the request and blocks it if it matches any of the configured regex patterns.
func (p *RegexBlock) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ipNet, ip := p.getClientIP(req)
	if ipNet == nil {
		p.logger.Debug(fmt.Sprintf("Could not determine client IP from RemoteAddr %s. Allowing request.", req.RemoteAddr))
		p.next.ServeHTTP(rw, req)
		return
	}

	p.logger.Debug(fmt.Sprintf(
		"Testing IP %s. RemoteAddr=%s, %s=%s, path=%s.",
		ip,
		req.RemoteAddr,
		p.clientIPHeader,
		req.Header.Get(p.clientIPHeader),
		req.URL.Path,
	))

	// Check if IP is whitelisted.
	if p.isWhitelisted(ip) {
		p.next.ServeHTTP(rw, req)
		return
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Check if IP is blocked.
	if p.blockMgr.IsBlocked(ipNet) {
		p.logger.Debug(fmt.Sprintf("IP %s is still blocked.", ip))
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	// Check if the request matches any regex pattern.
	for _, pattern := range p.regexPatterns {
		if pattern.MatchString(req.URL.Path) {
			p.handleRegexMatch(rw, ipNet, ip, req, pattern.String())
			return
		}
	}

	// Allow the request to pass through.
	p.next.ServeHTTP(rw, req)
}

func (p *RegexBlock) handleRegexMatch(rw http.ResponseWriter, ipNet net.IP, ip string, req *http.Request, pattern string) {
    scheme := "http"
    if req.TLS != nil || req.Header.Get("X-Forwarded-Proto") == "https" {
        scheme = "https"
    }

    fullURL := fmt.Sprintf("%s://%s%s", scheme, req.Host, req.URL.RequestURI())

	if p.violationsBeforeBlock <= 1 {
		p.logger.Info(fmt.Sprintf("Setting block for IP %s for requested url %s, based on regex of %s.", ip, fullURL, pattern))
		err := p.blockMgr.Block(ipNet, p.blockDuration)
		if err != nil {
			p.logger.Error(fmt.Sprintf("Failed to block IP %s: %v", ip, err))
		}
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	count, err := p.violationMgr.AddViolation(ipNet, p.violationWindowSeconds)
	if err != nil {
		p.logger.Error(fmt.Sprintf("Failed to add violation for IP %s: %v", ip, err))
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	p.logger.Info(fmt.Sprintf(
		"Recorded violation %d/%d for IP %s for requested url %s, based on regex of %s.",
		count,
		p.violationsBeforeBlock,
		ip,
		fullURL,
		pattern,
	))

	if count >= p.violationsBeforeBlock {
		p.logger.Info(fmt.Sprintf("Violation threshold reached. Setting block for IP %s for %d minutes.", ip, p.blockDuration))
		err := p.blockMgr.Block(ipNet, p.blockDuration)
		if err != nil {
			p.logger.Error(fmt.Sprintf("Failed to block IP %s: %v", ip, err))
		}

		err = p.violationMgr.ClearViolations(ipNet)
		if err != nil {
			p.logger.Error(fmt.Sprintf("Failed to clear violations for IP %s: %v", ip, err))
		}
	}

	rw.WriteHeader(http.StatusNotFound)
}

// getClientIP returns the IP address that should be checked/blocked.
//
// Default behavior:
// - Use req.RemoteAddr.
//
// Trusted proxy behavior:
// - If the configured client IP header is present and the immediate peer
//   from req.RemoteAddr is inside trustedProxyCIDRs, use the header IP.
// - If trustedProxyCIDRs is empty and CF-Connecting-IP is present, fetch
//   Cloudflare IP ranges lazily, cache them for 24 hours, and retry on
//   future requests if the fetch fails.
func (p *RegexBlock) getClientIP(req *http.Request) (net.IP, string) {
	remoteIP := parseRemoteAddrIP(req.RemoteAddr)
	if remoteIP == nil {
		p.logger.Debug(fmt.Sprintf("Could not parse RemoteAddr %s.", req.RemoteAddr))
		return nil, ""
	}

	headerValue := strings.TrimSpace(req.Header.Get(p.clientIPHeader))
	if headerValue == "" {
		p.logger.Debug(fmt.Sprintf("No %s header present. Using RemoteAddr IP %s.", p.clientIPHeader, remoteIP.String()))
		return remoteIP, remoteIP.String()
	}

	headerIP := net.ParseIP(headerValue)
	if headerIP == nil {
		p.logger.Debug(fmt.Sprintf("Header %s value %q is invalid. Using RemoteAddr IP %s.", p.clientIPHeader, headerValue, remoteIP.String()))
		return remoteIP, remoteIP.String()
	}

	trustedNets := p.getTrustedProxyNets(req)
	if len(trustedNets) == 0 {
		p.logger.Debug(fmt.Sprintf("No trusted proxy CIDRs available. Ignoring %s=%s and using RemoteAddr IP %s.", p.clientIPHeader, headerIP.String(), remoteIP.String()))
		return remoteIP, remoteIP.String()
	}

	if ipInNets(remoteIP, trustedNets) {
		p.logger.Debug(fmt.Sprintf("RemoteAddr IP %s is trusted. Using %s IP %s.", remoteIP.String(), p.clientIPHeader, headerIP.String()))
		return headerIP, headerIP.String()
	}

	p.logger.Debug(fmt.Sprintf("RemoteAddr IP %s is not trusted. Ignoring %s=%s.", remoteIP.String(), p.clientIPHeader, headerIP.String()))
	return remoteIP, remoteIP.String()
}

// getTrustedProxyNets returns configured trusted proxies or a TTL-cached Cloudflare CIDR list.
func (p *RegexBlock) getTrustedProxyNets(req *http.Request) []*net.IPNet {
	p.cfFetchMu.RLock()
	hasValidCache := len(p.trustedProxyNets) > 0 &&
		!p.cfFetchedAt.IsZero() &&
		time.Since(p.cfFetchedAt) < p.cfCacheTTL

	if hasValidCache {
		nets := p.trustedProxyNets
		p.cfFetchMu.RUnlock()
		p.logger.Debug(fmt.Sprintf("Using cached trusted proxy CIDRs. Count=%d, age=%s.", len(nets), time.Since(p.cfFetchedAt).Round(time.Second)))
		return nets
	}

	// If the user configured trustedProxyCIDRs, never auto-fetch.
	// If they were invalid and none parsed, fail closed to RemoteAddr behavior.
	if len(p.trustedProxyCIDRs) > 0 {
		nets := p.trustedProxyNets
		p.cfFetchMu.RUnlock()
		p.logger.Debug(fmt.Sprintf("Using configured trusted proxy CIDRs. Count=%d.", len(nets)))
		return nets
	}

	p.cfFetchMu.RUnlock()

	// Only lazy-fetch Cloudflare ranges when CF-Connecting-IP is actually present.
	if req.Header.Get("CF-Connecting-IP") == "" {
		p.logger.Debug("CF-Connecting-IP header is not present. Skipping Cloudflare CIDR fetch.")
		return nil
	}

	p.cfFetchMu.Lock()

	// Re-check after acquiring write lock.
	hasValidCache = len(p.trustedProxyNets) > 0 &&
		!p.cfFetchedAt.IsZero() &&
		time.Since(p.cfFetchedAt) < p.cfCacheTTL

	if hasValidCache {
		nets := p.trustedProxyNets
		p.cfFetchMu.Unlock()
		p.logger.Debug(fmt.Sprintf("Using cached trusted proxy CIDRs after lock re-check. Count=%d, age=%s.", len(nets), time.Since(p.cfFetchedAt).Round(time.Second)))
		return nets
	}

	if p.cfFetchInFlight {
		// Another request is refreshing. Return stale cache if present; otherwise
		// return nil and fall back to RemoteAddr.
		nets := p.trustedProxyNets
		p.cfFetchMu.Unlock()
		p.logger.Debug(fmt.Sprintf("Cloudflare CIDR fetch is already in-flight. Using stale cache count=%d.", len(nets)))
		return nets
	}

	p.cfFetchInFlight = true
	p.cfFetchMu.Unlock()

	freshNets, err := p.fetchCloudflareCIDRs()

	p.cfFetchMu.Lock()
	p.cfFetchInFlight = false

	if err != nil {
		// Important: do NOT update cfFetchedAt on failure.
		// That means a future request can retry.
		p.logger.Error(fmt.Sprintf("Cloudflare trusted proxy CIDR fetch failed: %v", err))

		nets := p.trustedProxyNets
		p.cfFetchMu.Unlock()

		if len(nets) > 0 {
			p.logger.Debug(fmt.Sprintf("Using stale Cloudflare trusted proxy CIDR cache. Count=%d.", len(nets)))
		} else {
			p.logger.Debug("No stale Cloudflare trusted proxy CIDR cache available.")
		}

		return nets
	}

	p.trustedProxyNets = freshNets
	p.cfFetchedAt = time.Now()

	nets := p.trustedProxyNets
	p.cfFetchMu.Unlock()

	p.logger.Info(fmt.Sprintf("Cloudflare trusted proxy CIDR cache refreshed. Count=%d, ttl=%s.", len(nets), p.cfCacheTTL))

	return nets
}

func (p *RegexBlock) fetchCloudflareCIDRs() ([]*net.IPNet, error) {
	p.logger.Info("Fetching Cloudflare trusted proxy CIDRs.")

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	urls := []string{
		"https://www.cloudflare.com/ips-v4",
		"https://www.cloudflare.com/ips-v6",
	}

	nets := make([]*net.IPNet, 0)

	for _, url := range urls {
		p.logger.Debug(fmt.Sprintf("Fetching Cloudflare CIDRs from %s.", url))

		resp, err := client.Get(url)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("unexpected status from %s: %s", url, resp.Status)
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				p.logger.Error(fmt.Sprintf("Cloudflare CIDR %s from %s is invalid and will not be used.", line, url))
				continue
			}

			nets = append(nets, ipNet)
			p.logger.Debug(fmt.Sprintf("Adding Cloudflare trusted proxy CIDR %s.", line))
		}

		err = scanner.Err()
		_ = resp.Body.Close()

		if err != nil {
			return nil, err
		}
	}

	if len(nets) == 0 {
		return nil, errors.New("no Cloudflare CIDRs loaded")
	}

	p.logger.Info(fmt.Sprintf("Loaded %d Cloudflare trusted proxy CIDRs.", len(nets)))

	return nets, nil
}

// isWhitelisted checks if the IP address is whitelisted.
func (p *RegexBlock) isWhitelisted(ip string) bool {
	p.logger.Debug(fmt.Sprintf("Checking if IP %s is in whitelist", ip))

	addr := net.ParseIP(ip)
	if addr == nil {
		p.logger.Debug(fmt.Sprintf("Could not parse request IP %s", ip))
		return false
	}

	for _, ipNet := range p.whitelist {
		if ipNet.Contains(addr) {
			p.logger.Debug(fmt.Sprintf("IP %s is in whitelist", ip))
			return true
		}
	}

	p.logger.Debug(fmt.Sprintf("IP %s is not in whitelist", ip))
	return false
}

func parseRemoteAddrIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	return net.ParseIP(host)
}

func parseIPOrCIDR(value string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(value)
	if err == nil {
		return ipNet
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return nil
	}

	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}

	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}

	for _, ipNet := range nets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}
