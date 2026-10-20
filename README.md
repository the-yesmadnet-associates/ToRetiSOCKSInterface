# ToRetiSOCKSInterface

*Version 2.4-tor - October 2026*

SOCKS5 client interface for [Reticulum](https://reticulum.network/), tuned for Tor.
Tested and used on the ToReticuLoki Gateways, the Buttcave Nexus and a few other gateways.

With more and more public, Tor-based gateways popping up on rmap, we came up with the idea of publishing ToRetiSOCKSInterface - the interface we have been using ourselves for a while.

It is based on `SOCKSClientInterface.py` by Kevin Steen
([SkyGuy on Codeberg](https://codeberg.org/SkyGuy/reti_socks_client)). The first versions were
simple modifications - later most of the code was rewritten.

We wanted to offer a thoroughly tested and reliable alternative, so users don’t have to risk running freshly thrown-together or untrusted interfaces that could leak IPs or cause other problems.

## How is it different?

Let's pop the hood and look under it.

**What we kept - because it worked well**:

1. HDLC framing (the wire format is unchanged, so it stays compatible with Reticulum's TCP interfaces)
2. The SOCKS5 username/password stream isolation technique (Kevin's design)

**What we changed - because we needed it**:

1. **The MTU follows the bitrate.** Kevin's version deliberately locks the Link MTU to Reticulum's
   default of 500 bytes. ToRetiSOCKSInterface sets `AUTOCONFIGURE_MTU`, so the interface MTU is derived
   from `bitrate` (20 Mbit/s gives 16384).
   
   In our initial loopback tests (using RNS 1.5.7, a local SOCKS5 proxy, and a 2-20 Mbit/s bitrate), this meant a Link MTU of 4096-16384 instead of 500, dropping a 2 MiB transfer from about 5 seconds down to roughly 0.4 to 0.8 seconds. The improvement was also noticeable in our real-world tests, although results varied depending on the gateway and Tor circuit.
2. Clearer SOCKS5 error messages, including Tor's onion service reply codes (like 0xF0-0xF7)
3. A configurable `connect_timeout`
4. Default bitrate set to 20 Mbit/s. It seemed to be a good fit during our tests, but feel free to experiment.
5. More robust reconnect handling (as: exponential backoff with jitter, tunable keepalive, etc) and better logging
6. Hostnames and `.onion` addresses are always resolved by the proxy, never locally. IPv4 and IPv6
   literals are sent as they are.
7. Various small clean-ups and configuration options: `bitrate`, `hw_mtu`, `isolate`, `connect_timeout`,
   buffer and keepalive settings

## Will it be blazing fast?

Of course not. It depends on many things: the Tor network itself, the relays and exit nodes,
the geographical location of nodes and gateways, the gateway's bandwidth and response time,
your own bandwidth and response time, and of course Reticulum itself. So all in all, it is always a gamble.

The best speed we could achieve...

...to a clearnet gateway through Tor: about 10-12 Mbps
...to a Tor-based gateway: about 6-7 Mbps

Technically - it can be faster. 
Practically - rarely.

## Is it stable?

Absolutely - at least for us! The ToReticuLoki Gateways' clearnet connections have been running through this interface for the past weeks.

## Is this crucial?

Absolutely - not! You can stick with SkyGuy's version, it works as intended.
However, after almost 6 months of experience with the ToReticuLoki Gateways and feedback, we wanted to make an interface
that is better tuned for our needs, and, well: sharing is caring, so we hope it can be put to good use by the community.

## I think I could improve it...

Contributions are welcome! If you find a bug in the reconnect loop, have an idea to optimize the HDLC buffer,
or want to improve the logging, feel free to open an Issue or submit a Pull Request - or preferably: just contact one of us via lxmf.

GitHub is mainly for publishing, our real work happens on NomadNet, check the ToReticuLoki Gateways: '436ef889d637b2aa78dd3d7f0b3b10fb:/page/index.mu'.

## How does it work?

1. Install Reticulum.
2. Install the Tor daemon (its default SOCKS port is 9050; Tor Browser uses 9150).
3. Download `ToRetiSOCKSInterface.py` and copy it into the `interfaces` folder inside your Reticulum config directory.
   The file name must match the `type` you use in the config. (So just change the `BackboneInterface` or `TCPClientInterface` to `ToRetiSOCKSInterface`)
4. Add an interface to your Reticulum config, just like this:

To connect to a clearnet gateway (through Tor):

```
[[Clearnet Gateway]]
  type = ToRetiSOCKSInterface
  enabled = yes
  target_host = example.net
  target_port = 4242
```

To connect to a Tor-based gateway:

```
[[Tor Gateway]]
  type = ToRetiSOCKSInterface
  enabled = yes
  target_host = toraddress.onion
  target_port = 4965
```

Restart Reticulum and run `rnstatus`. And voilá, magic happens: the interface shows up as `ToRetiSOCKS[gatewayname]`. Feel free to test with any program (nomadnet, sideband, meshchat and else).

Optional keys if you need to change anything or experiment further: `proxy_host` (127.0.0.1), `proxy_port` (9050), `isolate` (yes), `bitrate` (20000000),
`connect_timeout` (20), `hw_mtu`, and several buffer and keepalive settings - have a look around.

## License and credits

AGPL-3.0-or-later, see `LICENSE`. No warranty.

Copyright 2025 Kevin Steen, copyright 2026 The Yesmadnet Associates (see `CREDITS`).
Based on `SOCKSClientInterface.py` by Kevin Steen: https://codeberg.org/SkyGuy/reti_socks_client

This project is not affiliated with Reticulum, NomadNet, Tor or RetiNet.

## Changelog

**2.4-tor** (October 2026), initial public release. Check the `What we changed` section.

**1.1.202503**: the original SOCKSClientInterface by Kevin Steen.
