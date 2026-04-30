# traefik-regex-block

## Summary
The `traefix-regex-block` plugin provides middleware for Traefik to detect URLs that match a list of regex patterns
and then block those IP addresses for a configurable amount of time. This project took inspiration from the well
known `Fail2Ban` application. This plugin can improve security of a site by detecting when threat actors are
scanning your site for known exploitable endpoints. If there are certain patterns that are often scanned for that
you know will not be on your site, you can proactively identify when those attempts are made and block the source
from further scanning of your site.

This plugin now supports proxies out of the box, the previous version of this plugin didn't take
proxies into account and was updated to support Cloudflare IP's and other proxy
implementations using CF-Connecting-IP or X-Forwarded-For headers.

## Installation

Installation instructions can be found on the [Traefik plugin catalog](https://plugins.traefik.io/plugins/65f7bc4d46079255c9ffd1f0/regex-block).

## Latest Release
The current release is version **v0.1.0**. This plugin is still in it's early development phase. However, it is fully functional and is in bug testing phase. If you encounter any problems, please provide feedback by [opening an issue here](https://github.com/tkreiner/traefik-regex-block/issues).

## Configuration
The following settings can be used to configure the plugin.

### Block Duration - blockDurationMinutes
* Required: No
* Default: 60 minutes

Use this setting to determine how many minutes an IP address will be blocked from your site after each URL attempt that matches a regex pattern.

The number of minutes an IP address remains blocked after it reaches the blocking threshold.

```yaml
blockDurationMinutes: 120
```

### Regular Expression Pattern List - regexPatterns
* Required: Yes
* Default: (none)

You provide a list of regular expression patterns to be used to detect activity you want to block. You can provide any number of patterns to monitor with.

### Whitelist IP Addresses - whitelist
* Required: No
* Default: (none)

If you want to keep from blocking specific IP addresses, you can use the whitelist feature. This accepts a list of IP addresses as either an IP address on in CIDR notation.

```yaml
whitelist:
  - 127.0.0.1
  - 192.168.0.0/16
  - 2001:db8::/32
```

### Enable Debug Logging - enableDebug
* Required: No
* Default: false

Setting this value to true will show all debug logging for the plugin. Otherwise, logging level is set to an info level for output.

```yaml
enableDebug: true
```

### Maximum Blocked IPs - maxBlockedIPs

- Required: No
- Default: `0` / unlimited

Limits the number of currently blocked IP addresses held by the in-memory block manager. When the limit is reached, the oldest blocked IP is evicted before adding a new one.

Unset, `0`, or a negative value means unlimited.

```yaml
maxBlockedIPs: 10000
```

### Violations Before Block - `violationsBeforeBlock`

- Required: No
- Default: `1`

Controls how many regex-matching requests an IP must make before it becomes blocked.

The default value of `1` preserves the original behavior: the first matching request immediately creates a block.

When set higher than `1`, matching requests are counted as violations within the configured violation window. Regex-matching requests still receive a `404` response, but the IP is not blocked until the threshold is reached.

```yaml
violationsBeforeBlock: 3
```

### Violation Window - `violationWindowSeconds`

- Required: No
- Default: `300`

The number of seconds violation counts remain active before expiring. This setting only matters when `violationsBeforeBlock` is greater than `1`.

```yaml
violationWindowSeconds: 300
```

### Maximum Violation IPs - `maxViolationIPs`

- Required: No
- Default: `0` / unlimited

Limits the number of IP addresses held in the in-memory violation tracker. This helps prevent memory growth on high-traffic systems or under distributed scanning attempts.

When the limit is reached, the oldest violation-tracked IP is evicted before adding a new one.

Unset, `0`, or a negative value means unlimited. If unset maxBlockedIPs will be used.

```yaml
maxViolationIPs: 50000
```

### Client IP Header - `clientIPHeader`

- Required: No
- Default: `CF-Connecting-IP`

The request header to use as the real client IP when the immediate peer is a trusted proxy. Can be also set as X-Forwarded-For if using an internal load balancer outside of Cloudflare.

```yaml
clientIPHeader: CF-Connecting-IP
```

### Trusted Proxy CIDRs - `trustedProxyCIDRs`

- Required: No
- Default: none

A list of trusted proxy CIDRs. If the request's immediate peer IP is inside one of these ranges, the plugin may use `clientIPHeader` as the real client IP.

If this list is empty and `CF-Connecting-IP` is present, the plugin lazily fetches Cloudflare's published IPv4 and IPv6 ranges, caches them for 24 hours, and retries on a future request if the fetch fails.

```yaml
trustedProxyCIDRs:
  - 173.245.48.0/20
  - 103.21.244.0/22
  - 2606:4700::/32
```

### Example
The following configuration will detect any URL traffic that includes `/.env` or `/cgi-bin` in the URL. It will block any further requests from the IP address for 2 hours. Logging level is set to show debug messages. It then excludes blocking for any requests from the `127.0.0.1` address, or from a `192.168.0.0/16` network.  It limits blocked IP memory to 10,000 entries and violation tracking memory to 50,000 entries.

```yaml
http:
  middlewares:
    block-bad-paths:
      plugin:
        regex-block:
          blockDurationMinutes: 120
          enableDebug: true

          maxBlockedIPs: 10000
          violationsBeforeBlock: 3
          violationWindowSeconds: 300
          maxViolationIPs: 50000

          clientIPHeader: CF-Connecting-IP

          regexPatterns:
            - \/\.env
            - \/cgi-bin

          whitelist:
            - 127.0.0.1
            - 192.168.0.0/16
```

Then reference the middleware from a router:

```yaml
http:
  routers:
    my-app:
      rule: Host(`example.com`)
      entryPoints:
        - websecure
      tls: true
      service: my-app
      middlewares:
        - block-bad-paths
```

## Behavior Notes

- A regex match returns `404 Not Found` to preserve scanner-hiding behavior.
- Once an IP is blocked, future requests receive `403 Forbidden` until the block expires.
- `violationsBeforeBlock: 1` preserves immediate-block behavior.
- `maxBlockedIPs` and `maxViolationIPs` only apply to the in-memory storage backend.
- HTTP middleware only runs on Traefik HTTP routers. It will not run on TCP routers or TLS passthrough routers.
