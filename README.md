# ipscout

Quick triage for a list of IP addresses. For each IP, `ipscout` finds:

- **Reverse DNS**: the hostname the IP points back to
- **Ownership and location**: country, region, city, ASN and organisation (via [ipinfo.io](https://ipinfo.io))
- **Reputation** *(optional)*: how many VirusTotal engines flag it as malicious or suspicious

It's useful when you've pulled IPs out of firewall logs, flow logs, an alert or a phishing email and want a quick idea of who they belong to and whether they're known to be bad.

Python 3.10+, standard library only. Nothing to `pip install`.

## Usage

```bash
./ipscout.py examples/ips.txt
```

```
IP                    CC  ASN      Organisation        Reverse DNS
--------------------  --  -------  ------------------  ---------------
8.8.8.8               US  AS15169  Google LLC          dns.google
1.1.1.1               AU  AS13335  Cloudflare, Inc.    one.one.one.one
9.9.9.9               US  AS19281  Quad9               dns9.quad9.net
2001:4860:4860::8888  US  AS15169  Google LLC          dns.google
192.168.1.10                       (private/reserved)
```

With VirusTotal reputation and saved results:

```bash
export VT_API_KEY=...            # your VirusTotal API key
./ipscout.py suspicious.txt --vt --csv results.csv --json results.json
```

Reading from a pipe, for example IPs pulled from a log:

```bash
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/auth.log | sort -u | ./ipscout.py -
```

### Input format

One IP per line. IPv4 and IPv6 are both supported. Blank lines and `#` comments are ignored, duplicates are removed, and invalid lines are reported as warnings without stopping the run.

Private and reserved addresses (RFC 1918, loopback, link-local and so on) are never sent to external services.

### Options

| Option | Description |
|---|---|
| `--vt` | Look up reputation on VirusTotal (needs `VT_API_KEY`) |
| `--vt-delay N` | Seconds between VirusTotal calls. Default 15, to stay within the free tier's 4 requests/minute. Use `0` with a premium key. |
| `--csv PATH` / `--json PATH` | Also save results to a file |
| `--workers N` | Parallel reverse DNS / ipinfo lookups (default 8) |
| `-q` | Hide progress messages |

### API keys

| Variable | Needed? | Notes |
|---|---|---|
| `VT_API_KEY` | Only with `--vt` | Free key at [virustotal.com](https://www.virustotal.com/gui/join-us): 4 lookups/min, 500/day |
| `IPINFO_TOKEN` | Optional | Without it ipinfo.io limits anonymous requests. A free token at [ipinfo.io/signup](https://ipinfo.io/signup) gives a much higher limit. |

Keys are read from environment variables only, so they don't end up in your shell history or in `ps` output.

## Output fields (CSV/JSON)

`ip, scope, rdns, country, region, city, asn, org, vt_verdict, vt_malicious, vt_suspicious, vt_harmless, vt_undetected, vt_reputation, vt_link, error`

`vt_verdict` is one of:
- `MALICIOUS`: at least one engine flags the IP as malicious
- `SUSPICIOUS`: no malicious flags, but at least one suspicious flag
- `clean`
- `not found`: VirusTotal has no record of the IP

The exit code is `1` if any lookup failed, so the script can be used in pipelines.

## Things to keep in mind

- **Geolocation is approximate.** It shows where the IP block is registered or routed, not where a person is. CDNs, VPNs and cloud providers make this especially loose.
- **A clean VirusTotal result doesn't mean safe.** It only means no engine has flagged the IP *yet*. New attacker infrastructure is often clean.
- **Privacy.** The public IPs you look up are sent to ipinfo.io and, with `--vt`, to VirusTotal. Don't submit IPs you're not allowed to share. Result files are git-ignored by default because they may contain investigation data.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests mock all network calls, so they run offline. GitHub Actions runs them on Python 3.10, 3.12 and 3.14.

## Roadmap ideas

- [ ] AbuseIPDB and GreyNoise as extra reputation sources
- [ ] Cache results locally so repeat lookups don't use up API quota
- [ ] Read IPs directly from common log formats
- [ ] HTML report output

## License

MIT
