# vpn-client-pia-wireguard-posix-shell

short: piavpn

rewrite of https://github.com/pia-foss/manual-connections

the goal was to run this on an openwrt router, but

1. openwrt's curl lacks the `--connect-to "$name::$ip:"` feature
1. `wg-quick` is written in bash, so we would need to port that too ...



## sample output

<pre>
<span color="turquoise">[user@nixos:~]$</span> sudo dash vpn-pia.posix.sh

usage:
run_setup.refactor.posix.headless.sh [--config CONFIG] command

commands:
  connect --> connect to VPN server
  regions --> show regions, sorted by latency
  servers --> show servers, sorted by latency

options:
  --config CONFIG --> use CONFIG as config file
                      default: /etc/piavpn.config.sh
</pre>

### connect

<pre>
<span color="turquoise">[user@nixos:~]$</span> sudo dash vpn-pia.posix.sh connect

<span color="green">SUCCESS</span> IPv6 is now disabled for better security. To enable IPv6 again, run: sysctl -w net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
<span color="green">INFO</span> Login ...
<span color="green">SUCCESS</span> Login done, expires 2021-08-27T11:01:57Z+0200
<span color="green">SUCCESS</span> Port Forwarding is enabled, will show only servers with PF
<span color="green">INFO</span> region spain -&gt; server madrid402 at 212.102.49.14
<span color="green">INFO</span> Disable old Wireguard connection: wg-quick down 'pia'
.wg-quick-wrapped: `pia' is not a WireGuard interface
<span color="green">INFO</span> Write Wireguard config to /etc/wireguard/pia.conf
<span color="green">INFO</span> Start Wireguard connection: wg-quick up 'pia'
[#] ip link add pia type wireguard
[#] wg setconf pia /dev/fd/63
[#] ip -4 address add 10.13.169.5 dev pia
[#] ip link set mtu 1420 up dev pia
[#] resolvconf -a pia -m 0 -x
[#] wg set pia fwmark 12345
[#] ip -4 route add 0.0.0.0/0 dev pia table 12345
[#] ip -4 rule add not fwmark 12345 table 12345
[#] ip -4 rule add table main suppress_prefixlength 0
[#] sysctl -q net.ipv4.conf.all.src_valid_mark=1
[#] nft -f /dev/fd/63
<span color="green">INFO</span> Test ping to DNS server: ping '10.0.0.243'
<span color="green">INFO</span> Test DNS: getent ahostsv4 privateinternetaccess.com
<span color="green">INFO</span> Test TCP: curl -I -4 http://privateinternetaccess.com/
<span color="green">SUCCESS</span> Connected to Wireguard server madrid402
<span color="green">INFO</span> To disconnect from VPN, run: wg-quick down pia
<span color="green">INFO</span> Port Forwarding: Bind port 23456 ...
<span color="green">INFO</span> Bound port 23456 on 2021-08-26 11:02:01 +0200
<span color="green">INFO</span> Wait for portforwarding to take effect ...
<span color="green">SUCCESS</span> Connection to 212.102.49.14 23456 port [tcp/*] succeeded!
<span color="green">SUCCESS</span> Connection to 212.102.49.14 23456 port [udp/*] succeeded!
<span color="green">INFO</span> Local firewall: Port 23456 is now open for TCP and UDP protocol
<span color="green">INFO</span> Port Forwarding: Bind port 23456 on server 212.102.49.14 (madrid402) every 15 minutes ...
....................................................................................................
<span color="green">INFO</span> Refreshed port 23456 on server 212.102.49.14 (madrid402) on 2021-08-27 12:17:54 +0200
...................................................................................................
<span color="green">INFO</span> Refreshed port 23456 on server 212.102.49.14 (madrid402) on 2021-08-28 13:19:01 +0200
...................................................................................................
</pre>

### regions

compare regions by latency

<pre>
<span color="turquoise">[user@nixos:~]$</span> time sudo dash vpn-pia.posix.sh regions

<span color="green">SUCCESS</span> Port Forwarding is enabled, will show only servers with PF

198.94 qatar Qatar
198.73 ca_vancouver CA Vancouver
197.87 mexico Mexico

[...]

42.47 morocco Morocco
42.32 nigeria Nigeria
41.19 dz Algeria

real	0m2.881s
</pre>

### servers

compare servers by latency

68 servers are pinged in 2.5 seconds

output of the `servers` command can be copy-pasted to the config file

<pre>
<span color="turquoise">[user@nixos:~]$</span> time sudo dash vpn-pia.posix.sh servers

<span color="green">SUCCESS</span> Port Forwarding is enabled, will show only servers with PF
<span color="green">INFO</span> Showing servers only for protocol wireguard (key wg)

198.80 country=QA; region=qatar # Qatar
  protocol=wireguard; server_ip=95.181.234.9; server_name=qatar403

196.82 country=PA; region=panama # Panama
  protocol=wireguard; server_ip=91.90.126.6; server_name=panama403

192.07 country=IN; region=in # India
  protocol=wireguard; server_ip=45.120.139.133; server_name=mumbai402

[...]

41.33 country=DZ; region=dz # Algeria
  protocol=wireguard; server_ip=176.125.228.5; server_name=algiers403

41.29 country=AD; region=ad # Andorra
  protocol=wireguard; server_ip=188.241.82.16; server_name=andorra404

41.13 country=NG; region=nigeria # Nigeria
  protocol=wireguard; server_ip=146.70.65.145; server_name=nigeria406

real	0m2.407s
```
