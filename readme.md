# vpn-client-pia-wireguard-posix-shell

short: piavpn

rewrite of https://github.com/pia-foss/manual-connections

the goal was to run this on an openwrt router, but

1. openwrt's curl lacks the `--connect-to "$name::$ip:"` feature
1. `wg-quick` is written in bash, so we would need to port that too ...



### sample output

<pre>
<span color="turquoise">[user@nixos:~]$</span> ~/bin/_vpn connect
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
