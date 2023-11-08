## BlueCat provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [BlueCat]().

### Installation

#### Command line

```
pip install octodns-bluecat
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-bluecat==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-cloudflare.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_cloudflare
```

### Configuration

```yaml
providers:
  bluecat:
    class: octodns_bluecat.BlueCatProvider
    # Your BlueCat instance
    endpoint: env/BLUECAT_ENDPOINT
    # Your BlueCat username (required, optional if using token)
    username: env/BLUECAT_USERNAME
    # Your BlueCAt password (required, optional if using token)
    password: env/BLUECAT_PASSWORD
    # The API Token or API Key.
    # Required permissions for API Tokens are Zone:Read, DNS:Read and DNS:Key.
    token: env/BLUECAT_TOKEN
    # Manage Page Rules (URLFWD) records
    # pagerules: true
    # Optional. Default: 4. Number of times to retry if a 429 response
    # is received.
    #retry_count: 4
    # Optional. Default: 300. Number of seconds to wait before retrying.
    #retry_period: 300
    # Optional. Default: 50. Number of zones per page.
    #zones_per_page: 50
    # Optional. Default: 100. Number of dns records per page.
    #records_per_page: 100
```

Note: The "proxied" flag of "A", "AAAA" and "CNAME" records can be managed via the YAML provider like so:

```yaml
name:
    octodns:
        bluecat:
            proxied: true
    ttl: 120
    type: A
    value: 1.2.3.4
```

### Support Information

#### Records

BlueCatProvider supports A, AAAA, ALIAS, CAA, CNAME, LOC, MX, NAPTR, NS, PTR, SPF, SRV, SSHFP, TXT, and URLFWD. There are restrictions on CAA tag support.

#### Root NS Records

BlueCatProvider does not supports root NS record management. They can partially be managed in the API, errors are thrown if you include the BlueCatProvider name servers in the values, but the system completely ignores the values set and serves up its own regardless.

#### Dynamic

BlueCatProvider does not support dynamic records.

#### Required API Token Permissions

Required Permissions for API Token are Zone:Read, DNS:Read, and DNS:Edit.

### Developement

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
