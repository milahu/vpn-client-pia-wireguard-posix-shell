#!/bin/sh

# license = CC0-1.0 = zero limits + zero warranty

# posix shells: dash ash (posh?)

# install to openwrt:
# scp vpn-pia.posix.sh wg-quick.posix.sh ca.rsa.4096.crt root@192.168.1.1:/root/
# cp piavpn.config.sh.sample piavpn.config.sh
# nano piavpn.config.sh # edit your config
# scp piavpn.config.sh root@192.168.1.1:/etc/

# FIXME wg-quick.posix.sh fails on openwrt
# 
# INFO Start Wireguard connection: ./wg-quick.posix.sh up 'pia'
# [#] ip link add pia type wireguard
# [#] wg setconf pia /tmp/tmp.ijGMpM
# [#] ip -4 address add 10.7.135.47 dev pia
# sed: unmatched ':'
# sed: unmatched ':'
# [#] ip link set mtu 1420 up dev pia
# ./wg-quick.posix.sh: line 442: can't open /etc/resolvconf/interface-order: no such file
# [#] resolvconf -a pia -m 0 -x
# ./wg-quick.posix.sh: line 222: resolvconf: not found
# [#] ip link delete dev pia
# FATAL Failed to start Wireguard interface 'pia'
# root@OpenWrt:~# resolvconf
# -ash: resolvconf: not found

# FIXME
# INFO Refreshed port 21051 on server 212.102.49.36 (madrid402) on 2021-05-01 03:25:27 +0200
# ...........................curl: (28) Failed to connect to 10.35.128.1 port 19999: Connection timed out
# ERROR Port refresh failed on 2021-05-01 10:27:50 +0200. server response: {"client_error":""}
# problem was: server changed! region=spain:
#protocol=wireguard; server_ip=212.102.49.36; server_name=madrid402 # old
#protocol=wireguard; server_ip=212.102.49.107; server_name=madrid401 # new
# TODO allow to select server by region

# FIXME disable vpn (wg-quick down pia) before login
# INFO Login ...

# FIXME reuse port for PF https://github.com/pia-foss/manual-connections/issues/121

# dependencies on openwrt:
# wireguard-tools: 30KB
# curl: 50KB TODO -> use wget (installed by default on openwrt)
# jq: 100KB [oof!]
# coreutils-timeout: 20KB TODO avoid
# ca.rsa.4096.crt from pia-foss

# FIXME wg-quick: not found + FIXME: wg-quick is written in bash :((

# TODO save mirrorlist offline + verify with signature + update in regular intervals (every week?)

# TODO add 'exit trap': print "run 'wg-quick down pia' to stop wireguard."

# ...
# uci set network.wg0.fwmark='0xTODO'
# uci add network wireguard_wg0 # =cfg0d96fc
# uci set network.@wireguard_wg0[-1].endpoint_port='1337'
# uci set network.@wireguard_wg0[-1].public_key='75hrwEZJ+scInKAphJOBNm11YDuumNQ6FouSXc215y8='
# uci set network.@wireguard_wg0[-1].endpoint_host='212.102.49.36'
# uci add_list network.@wireguard_wg0[-1].allowed_ips='0.0.0.0/0'
# uci add_list network.wg0.addresses='10.35.147.134'
# uci set network.@wireguard_wg0[-1].description='pia'



#todo fix:

#INFO Port Forwarding: Bind port 25311 ...
#INFO Bound port 25311 on 2021-03-05 01:09:12 +0100
#INFO Wait for portforwarding to take effect ...
#Error: inet address is expected rather than "192.168.1.1
#192.168.1.1".
#RTNETLINK answers: No such process
#FATAL portforwarding is not working after 10 seconds





# openwrt ...
if false; then
  # /etc/config/firewall
  #uci set firewall.cfg03dc81.network='wan wan6 pia'
  uci set firewall.@zone[1].network='wan wan6 pia'
  # /etc/config/network
  uci set network.pia=interface
  uci set network.pia.proto='wireguard'
  uci add network wireguard_pia # =cfg0d79a8
  uci set network.pia.delegate='0'
  uci add_list network.pia.addresses='10.35.147.134'
  uci set network.pia.private_key='4AZBMIkGugolwVu+4ZaUbMx3qUnwtcERDCB/6d37+Fw='
  uci set network.@wireguard_pia[0].public_key='75hrwEZJ+scInKAphJOBNm11YDuumNQ6FouSXc215y8='
  uci set network.@wireguard_pia[0].description='pia-madrid'
  uci add_list network.@wireguard_pia[0].allowed_ips='0.0.0.0/0'
  uci set network.@wireguard_pia[0].endpoint_host='212.102.49.36'
  uci set network.@wireguard_pia[0].endpoint_port='1337'
  uci set network.@wireguard_pia[0].route_allowed_ips="1"
  uci commit



  # https://openwrt.org/docs/guide-user/services/vpn/wireguard/client

  # Install packages
  opkg update
  opkg install wireguard
  
  # Configuration parameters
  WG_IF="wg0"
  WG_SERV="212.102.49.36"
  WG_PORT="1337"
  WG_ADDR="10.35.147.134"
  WG_ADDR6=""

  # Generate keys
  umask go=
  wg genkey | tee wgclient.key | wg pubkey > wgclient.pub
  
  # Client private key
  #WG_KEY="$(cat wgclient.key)"
  WG_KEY='4AZBMIkGugolwVu+4ZaUbMx3qUnwtcERDCB/6d37+Fw='
  
  # Pre-shared key
  #WG_PSK="$(cat wgserver.psk)"
  
  # Server public key
  #WG_PUB="$(cat wgserver.pub)"
  WG_PUB='75hrwEZJ+scInKAphJOBNm11YDuumNQ6FouSXc215y8='


  # Configure firewall
  #uci rename firewall.@zone[0]="lan"
  #uci rename firewall.@zone[1]="wan"
  #uci del_list firewall.wan.network="${WG_IF}"
  #uci add_list firewall.wan.network="${WG_IF}"
  uci set firewall.@zone[1].network="wan wan6 ${WG_IF}"
  uci commit firewall
  /etc/init.d/firewall restart

  # Configure network
  uci -q delete network.${WG_IF}
  uci set network.${WG_IF}="interface"
  uci set network.${WG_IF}.proto="wireguard"
  uci set network.${WG_IF}.private_key="${WG_KEY}"
  uci add_list network.${WG_IF}.addresses="${WG_ADDR}"
  #uci add_list network.${WG_IF}.addresses="${WG_ADDR6}"
  uci set network.${WG_IF}.delegate='0'
  uci set network.${WG_IF}.nohostroute='1' # Do not add routes to ensure the tunnel endpoints are routed via non-tunnel device
  #uci set network.${WG_IF}.fwmark='0xTODO' # Firewall mark to apply to tunnel endpoint packets

  # Dynamic connection
  # https://openwrt.org/docs/guide-user/services/vpn/wireguard/extras#dynamic_connection
  # Preserve default route to restore WAN connectivity when VPN is disconnected.
  uci set network.wan.metric="100"
  uci set network.wan6.metric="100"

  # Add VPN peers
  uci -q delete network.wgserver
  uci set network.wgserver="wireguard_${WG_IF}"
  uci set network.wgserver.public_key="${WG_PUB}"
  #uci set network.wgserver.preshared_key="${WG_PSK}"
  uci set network.wgserver.endpoint_host="${WG_SERV}"
  uci set network.wgserver.endpoint_port="${WG_PORT}"
  uci set network.wgserver.route_allowed_ips="1" # Automatically create a route for each Allowed IPs for this peer
  uci set network.wgserver.persistent_keepalive="25"
  uci add_list network.wgserver.allowed_ips="0.0.0.0/0"
  #uci add_list network.wgserver.allowed_ips="::/0"
  uci commit network
  /etc/init.d/network restart

  # -> creates iface wan_6 ?

  # Kill switch
  # https://openwrt.org/docs/guide-user/services/vpn/wireguard/extras#kill_switch
  # Prevent traffic leak on OpenWrt client isolating VPN interface in a separate firewall zone.

  # lan <-> vpn <-> wan

  # root@OpenWrt:~# uci show firewall | grep forwarding
  # firewall.@forwarding[0]=forwarding
  # firewall.@forwarding[0].src='lan'
  # firewall.@forwarding[0].dest='wan'
  uci rename firewall.@forwarding[0]="lan_wan"

  uci set firewall.lan_wan.enabled="0"
  uci -q delete firewall.vpn
  uci set firewall.vpn="zone"
  uci set firewall.vpn.name="vpn"
  uci set firewall.vpn.input="REJECT"
  uci set firewall.vpn.output="ACCEPT"
  uci set firewall.vpn.forward="REJECT"
  uci set firewall.vpn.masq="1"
  uci set firewall.vpn.mtu_fix="1"
  uci add_list firewall.vpn.network="vpn"
  uci del_list firewall.wan.network="vpn"
  uci -q delete firewall.lan_vpn
  uci set firewall.lan_vpn="forwarding"
  uci set firewall.lan_vpn.src="lan"
  uci set firewall.lan_vpn.dest="vpn"
  uci commit firewall
  /etc/init.d/firewall restart

  # internet not reachable :(

  # stop:
  uci -q delete network.${WG_IF}
  uci -q delete network.wgserver
  uci commit



  # https://openwrt.org/docs/guide-user/services/rng
  # Install packages
  opkg update
  opkg install rng-tools
  
  # Configure RNG
  uci set system.@rngd[0].enabled="1"
  uci commit system
  /etc/init.d/rngd restart



fi



# https://x-lore.kernel.org/wireguard/CACgDUr4BfbaLaP_csACp3Dk6c9GJ4py2w5TwurFjzZrhK1OPcQ@mail.gmail.com/T/
# FIXME
#   INFO Start Wireguard connection: ./wg-quick.posix.sh up 'pia'
#   [#] ip link add pia type wireguard
#   [#] wg setconf pia /dev/stdin
#   [#] ip -4 address add 10.33.247.95 dev pia
#   sed: -e expression #1, char 48: unterminated `s' command
#   [#] ip link delete dev pia
#   FATAL Failed to start Wireguard interface 'pia'
#wg_quick='./wg-quick.posix.sh'
wg_quick='wg-quick'



main() {
  # parse CLI arguments
  [ "$#" = '0' ] && { show_help; exit 0; }
  if [ "$1" = '--config' ]; then
    shift
    config_file="$1"
    shift
  fi
  # run command
  cmd="$1"
  [ "$cmd" = 'regions' ] && { show_regions; exit; }
  [ "$cmd" = 'servers' ] && { show_servers; exit; }
  [ "$cmd" = 'connect' ] && { do_connect; exit; }
}

# TODO allow to set server via command line interface
# like: piavpn.sh connect --protocol wireguard --server-ip 212.102.49.36 --server-name madrid402
do_connect() {
  load_config

  [ "$colorterm" != 'false' ] && enable_colors # default true
  [ "$disableipv6" != 'false' ] && disable_ipv6 # default true

  do_login

  # select server
  if [ ! -z "$server_ip" ]; then
    info "Use $protocol server '$server_name' at '$server_ip'"
  else
    get_serverlist_json

    filter_pf="$(get_filter_pf)"
    if [ ! -z "$region" ]; then
      trace "serverlist_json (region = '$region') = $(echo "$serverlist_json" | jq -r '.regions[] | select(.id == "'"$region"'")')"
      # jq filter
      #f='.regions[] | select(.id == "'"$region"'") '"$filter_pf"' | "\(.servers.meta[0].ip) \(.servers.meta[0].cn) \(.id) \(.name)"'
      f='.regions[] | select(.id == "'"$region"'") '"$filter_pf"' | "\(.servers.wg[0].ip) \(.servers.wg[0].cn) \(.id) \(.name)"'
    else
      error 'config is missing: no server was set'
      info 'please set a server with one of:'
      echo "server_region=your_server_region_id; # find region IDs with: $script_name regions"
      echo "server_ip=your_server_ip; server_name=your_server_name; # find server parameters with: $script_name servers"
      exit 1
    fi

    # todo: unused field (.geo|tostring) --> true | false
    ip_name_region_list="$(echo "$serverlist_json" | jq -r "$f")"
    trace "ip_name_region_list = $ip_name_region_list"
    while read ip_line; do
      server_ip="$(echo "$ip_line" | cut -d' ' -f1)"
      server_name="$(echo "$ip_line" | cut -d' ' -f2)"
      debug "server_name=$server_name; server_ip = $server_ip"
      break # use first server
    done << EOF
$ip_name_region_list
EOF
    info "region $region -> server $server_name at $server_ip"
  fi

  connect_to_server

  [ "$portforwarding" = 'true' ] && run_portforwarding
}

call_api() {
  name="$server_name"
  [ "$1" = '-v' ] && { ip="$server_vip"; shift; } || { ip="$server_ip"; }
  port="$1"; shift
  path="$1"; shift
  data="$@" # rest args
  curl_opts=''
  for key_val in $data; do
    curl_opts="${curl_opts} --data-urlencode $key_val"
  done

  trace2 call_api: $curl --get --connect-to "$name::$ip:" \
    --cacert "$api_certfile" $curl_opts \
    "https://${name}:${port}/${path}"

  res_json="$($curl --get --connect-to "$name::$ip:" \
    --cacert "$api_certfile" $curl_opts \
    "https://${name}:${port}/${path}")"
    #"https://${name}:${port}/${path}" 2>&1)"
    # FIXME 2>&1 also captures the curl progress meter, but we want to capture errors :(
    # -> use temp file to store download data?
    # curl progress meter + download data:
    #   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
    #                                  Dload  Upload   Total   Spent    Left  Speed
    # 0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0{
    #   ...json object...
    # }
  rc=$?

  if [ $rc -ne 0 ]; then
    res_json='{"client_error":"'"$(echo "$res_json" | sed 's/"/\\"/g')"'"}'
  fi

  if ( ! json_is "$res_json" .status OK ); then
    debug2 "api call failed to https://${name}:${port}/${path}"
    debug2 "response = $res_json"
  else
    trace2 "response = $res_json"
  fi
  echo "$res_json"
  return $rc
}

get_wireguard_conf() {
  addkey_json="$1"
  private_key="$2"

  # setdns: default true
  pia_conf_dns=''
  [ "$setdns" != 'false' ] && {
    dns_server=$(json_get "$addkey_json" .dns_servers[0])
    debug2 "dns_server = $dns_server"
    pia_conf_dns="DNS = $dns_server"
  }
  peer_ip=$(json_get "$addkey_json" .peer_ip)
  server_key=$(json_get "$addkey_json" .server_key)
  server_ip=$(json_get "$addkey_json" .server_ip)
  #server_vip=$(json_get "$addkey_json" .server_vip)
  server_port=$(json_get "$addkey_json" .server_port)

  cat <<EOF
# generated by ${script_name}

[Interface]
Address = ${peer_ip}
PrivateKey = ${private_key}
${pia_conf_dns}

[Peer]
PersistentKeepalive = 25
PublicKey = ${server_key}
AllowedIPs = 0.0.0.0/0
Endpoint = ${server_ip}:${server_port}

EOF
}

stop_wireguard() {
  warn "Disabe wireguard interface '${wireguard_ifname}': $wg_quick down '${wireguard_ifname}'"
  $wg_quick down "${wireguard_ifname}"
  $has_manual_gateway && ip route del "$server_ip"
}

connect_to_wireguard() {
  # TODO validate input: require $server_ip and $server_name

  private_key="$(wg genkey)"
  public_key="$(echo "$private_key" | wg pubkey)"
  debug "wireguard client public key: $public_key"

  addkey_json=$(call_api 1337 addKey "pt=${login_token}" "pubkey=${public_key}")
  # FIXME openwrt: parse error: Invalid numeric literal at line 1, column 4

  json_is "$addkey_json" .status OK || fatal failed on wireguard addkey

  # unused
  #res.server_vip == '12.34.56.78'
  #res.peer_pubkey == 'cACHgasdfuk0asdf/SCasdf8evijasdfasdfTZoasdf='

  # todo config
  wireguard_ifname=pia

  # todo check if connection exists
  info "Disable old Wireguard connection: $wg_quick down '${wireguard_ifname}'"
  $wg_quick down "${wireguard_ifname}"

  info 'Write Wireguard config to /etc/wireguard/pia.conf'
  mkdir -p '/etc/wireguard'

  # hide private key from other users
  touch "/etc/wireguard/${wireguard_ifname}.conf"
  chmod 0600 "/etc/wireguard/${wireguard_ifname}.conf"

  get_wireguard_conf "$addkey_json" "$private_key" \
  | tee "/etc/wireguard/${wireguard_ifname}.conf" >/dev/null

  server_ip=$(json_get "$addkey_json" .server_ip)
  server_vip=$(json_get "$addkey_json" .server_vip)
  peer_ip=$(json_get "$addkey_json" .peer_ip)

  info "Start Wireguard connection: $wg_quick up '$wireguard_ifname'"
  $wg_quick up "$wireguard_ifname" \
  || fatal "Failed to start Wireguard interface '${wireguard_ifname}'"

  # test the connection
  has_manual_gateway=false
  dns_server=$(json_get "$addkey_json" .dns_servers[0])
  timeout 1 ping -c1 "$dns_server" >/dev/null || {
    gateway="$(ip route list default | awk '{ print $3 }')"
    info "Wireguard server seems blocked by firewall (rp_filter?). workaround: ip route add '$server_ip' via '$gateway'"
    ip route add "$server_ip" via "$gateway"
    sleep 0.5 # wait for 'ip route add' to take effect
    has_manual_gateway=true
  }

  info "Test ping to DNS server: ping '$dns_server'"
  timeout 1 ping -c1 "$dns_server" >/dev/null \
  || { stop_wireguard; fatal ping to DNS server failed; }

  info 'Test DNS: getent ahostsv4 privateinternetaccess.com'
  timeout 1 getent ahostsv4 privateinternetaccess.com >/dev/null \
  || { stop_wireguard; fatal DNS is not working; }

  info 'Test TCP: curl -I -4 http://privateinternetaccess.com/'
  res="$($curl --head --max-time 1 --ipv4 http://privateinternetaccess.com/ 2>&1)" \
  || { error "$res"; stop_wireguard; fatal 'connection is not working'; }

  ## test IP and country
  #actual_ip = test_public_ip(res.server_ip)
  #if region:
  #  test_country(config, actual_ip, region)

  success "Connected to Wireguard server $server_name"
  if $has_manual_gateway
  then info "To disconnect from VPN, run: $wg_quick down $wireguard_ifname; ip route del $server_ip"
  else info "To disconnect from VPN, run: $wg_quick down $wireguard_ifname"
  fi
}

iptables_forward(){
  # iptables_forward --insert $port
  # iptables_forward --delete $port
  action="$1"
  port="$2"
  for direction in INPUT OUTPUT; do
    for protocol in tcp udp; do
      rule="$direction -p $protocol --dport $port -j ACCEPT"
      trace "call: iptables $action $rule"
      iptables $action $rule
    done
  done
}

run_portforwarding() {
  # todo: make more error-tolerant (retry on timeout)
  getsignature_json=$(call_api -v 19999 getSignature "token=${login_token}")
  json_is "$getsignature_json" .status OK || fatal failed on wireguard getSignature
  payload_base64="$(json_get "$getsignature_json" .payload)"
  signature="$(json_get "$getsignature_json" .signature)"
  payload_json="$(echo "$payload_base64" | base64 -d)"
  pf_expires_at="$(json_get "$payload_json" .expires_at)" #todo parse + on expire: request new port
  pf_port="$(json_get "$payload_json" .port)"
  #info "portforwarding: received port $pf_port"

  info "Port Forwarding: Bind port $pf_port ..."
  bindport_json=$(call_api -v 19999 bindPort "payload=${payload_base64}" "signature=${signature}")
  info "Bound port ${pf_port} on $(date "+$datetime_format")"

  # usually takes 5 seconds
  info 'Wait for portforwarding to take effect ...'
  sleep 4

  # add route to circumvent VPN tunnel, to allow port checking
  gateway="$(ip route list default | awk '{ print $3 }')"
  debug "Temporary: Skip VPN tunnel for VPN server at $server_ip: ip route add '$server_ip' via '$gateway'"
  ip route add "$server_ip" via "$gateway"
  sleep 0.5 # wait for 'ip route add' to take effect

  # start netcat server
  # TODO also test port forwarding with UDP protocol (not only TCP)
  debug "call: nc -l $pf_port &"
  nc -l "$pf_port" & # start netcat server
  nc_tcp_pid=$!
  trace "nc tcp server has pid $nc_tcp_pid"

  debug "call: nc -l -u $pf_port &"
  nc -l -u "$pf_port" & # start netcat server
  nc_udp_pid=$!
  trace "nc udp server has pid $nc_udp_pid"

  # some external port checkers -> no need to circumvent our VPN tunnel
  # https://portchecker.co/
  # http://porttest.net/
  # https://www.portcheckers.com/

  pf_is_working=false
  wait_for_pf=10
  for retry_num in $(seq 1 $wait_for_pf); do
    debug "test portforwarding: try $retry_num"
    # test connection
    debug "call: nc -v -z -n $server_ip $pf_port"
    res="$(timeout 1 nc -v -z -n "$server_ip" "$pf_port" 2>&1)" \
    && {
      success "$res"
      pf_is_working=true

      # test UDP protocol
      debug "call: nc -v -u -z -n $server_ip $pf_port"
      res="$(timeout 1 nc -v -u -z -n "$server_ip" "$pf_port" 2>&1)" \
      && {
        success "$res"
      } \
      || {
        error "Portforwarding is not working for UDP protocol"
      }
    } \
    || {
      debug "$res"
      debug "Forwarded port is not reachable -> open port in local firewall"

      # todo: remove old rules
      iptables_forward --insert $pf_port

      # test connection with firewall rule
      trace "call: nc -v -z -n $server_ip $pf_port"
      res="$(timeout 1 nc -v -z -n "$server_ip" "$pf_port" 2>&1)" \
      && {
        success "$res"
        pf_is_working=true

        # test UDP protocol
        debug "call: nc -v -u -z -n $server_ip $pf_port"
        res="$(timeout 1 nc -v -u -z -n "$server_ip" "$pf_port" 2>&1)" \
        && {
          success "$res"
        } \
        || {
          error "portforwarding is not working for UDP protocol"
        }

        info "Local firewall: Port $pf_port is now open for TCP and UDP protocol"
        # TODO how to close port?
      } \
      || {
        debug "$res"
        debug "local firewall: close TCP port $pf_port"
        iptables_forward --delete $pf_port
      }
    }
    $pf_is_working && break
    sleep 1
  done

  trace "kill nc tcp server with pid $nc_tcp_pid"
  kill $nc_tcp_pid # stop netcat server
  trace "kill nc udp server with pid $nc_udp_pid"
  kill $nc_udp_pid # stop netcat server
  debug "remove VPN bypass: ip route del '$server_ip'"
  ip route del "$server_ip"

  # todo restore
  ###################$pf_is_working || fatal "portforwarding is not working after $wait_for_pf seconds"

  pf_sleep=900 # 15 min
  pf_sleep_min=$(echo "$pf_sleep" | awk '{ print $1 / 60 }')
  info "Port Forwarding: Bind port $pf_port on server $server_ip ($server_name) every $pf_sleep_min minutes ..."
  sleep $pf_sleep

  # loop forever
  local step=0
  while true; do
    bindport_json=$(call_api -v 19999 bindPort "payload=${payload_base64}" "signature=${signature}")
    if (json_is "$bindport_json" .status OK)
    #then info "Refreshed port $pf_port on server $server_ip ($server_name) on $(date "+$datetime_format")"
    then
      if [ "$step" = '100' ]; then
        printf '\n'
        info "Refreshed port $pf_port on server $server_ip ($server_name) on $(date "+$datetime_format")"
        step=0
      else
        printf '.' # silent output
      fi
    else error "Port refresh failed on $(date "+$datetime_format"). server response: $bindport_json"
    fi
    sleep $pf_sleep
    step=$(( $step + 1 ))
  done
}

region_name_is_id() {
  name="$(echo "$1" | tr - _ | tr ' ' _)"
  id="$(echo "$2" | tr - _ )"
  echo "$name" | grep -qi "^$id\$"
}

# TODO use ping or netcat to measure latency, since we need root access anyway
# time nc -v -D -4 -n -w 1 -z $server_ip 443
# ping -c3 -w3 -n -q $server_ip | grep ^rtt | sed -E 's/^.* = ([^/]+)\/.*$/\1/'
parallel_tcp_ping_worker() {
  latency_result_file="$1"; ip_line="$2"
  server_ip="$(echo "$ip_line" | cut -d' ' -f1)"
  line_rest="$(echo "$ip_line" | cut -d' ' -f2-)"
  latency=$(LC_NUMERIC=en_US.utf8 curl \
    -s -o /dev/null --connect-timeout $maxlatency_sec \
    --write-out "%{time_connect}" http://$server_ip:443)
  latency=$(echo "$latency" | awk '{printf "%.2f\n", ($1 * 1000)}')
  # handle timeout. we add empty line to keep line count
  if [ "$latency" = '0.00' ]
  then echo >>"$latency_result_file"
  else echo "$latency $line_rest" >>"$latency_result_file"
  fi
}

parallel_tcp_ping() {
  ip_list="$1"; num_ips=$(echo "$ip_list" | wc -l)
  latency_result_file=$(tempfile latency_result.fifo)
  echo "$ip_list" | while read ip_line
  do
    parallel_tcp_ping_worker "$latency_result_file" "$ip_line" &
  done
  wait # wait for all background jobs
  sync # force file write. this is non-blocking
  # wait for file write
  while [ "$(cat "$latency_result_file" | wc -l)" != "$num_ips" ]
  do sleep 0.1; done
  latency_result="$(cat "$latency_result_file")"
  rm -f -- "$latency_result_file"
  echo "$latency_result" | grep -v '^$' # remove empty lines (timeouts)
}

get_filter_pf() {
  # portforwarding: default false
  if [ "$portforwarding" = 'true' ]; then
    success2 'Port Forwarding is enabled, will show only servers with PF'
    filter_pf='| select(.port_forward==true)'
  fi
  echo "$filter_pf"
}

# key in serverlist .region[].servers
get_key_for_protocol() {
  key=''
  [ -z "$protocol" ] && return
  [ "$protocol" = 'wireguard' ] && { echo wg; return; }
  if [ "$protocol" = 'openvpn' ]; then
    [ "$openvpn_protocol" = 'tcp' ] && { echo ovpntcp; return; }
    [ "$openvpn_protocol" = 'udp' ] && { echo ovpnudp; return; }
    return
  fi
  # todo: what is key 'ikev2'?
}

get_filter_protocol() {
  key=$(get_key_for_protocol)
  debug2 get_filter_protocol: key = $key
  [ -z "$key" ] && {
    #echo '| to_entries | select(.key!="meta") | from_entries'
    #echo '| select(.key!="meta")'
    echo '| select(.key!="meta" and .key!="ikev2")' # todo: what is ikev2?
    return
  }
  info2 "Showing servers only for protocol $protocol (key $key)"
  echo '| select(.key=="'"$key"'")'
  debug2 'get_filter_protocol: filter_protocol = ''| select(.key=="'"$key"'")'
}

show_regions() {
  # optionally use config: maxlatency, portforwarding
  load_config --ignore-error
  get_serverlist_json
  filter_pf="$(get_filter_pf)"
  # bug fixed: .name must come last (can contain whitespace)
  # jq filter
  f='.regions[] '"$filter_pf"' | "\(.servers.meta[0].ip) \(.id) \(.name)"'
  # todo: unused field (.geo|tostring) --> true | false
  ip_region_list="$(echo "$serverlist_json" | jq -r "$f")"
  latency_result="$(parallel_tcp_ping "$ip_region_list")"
  echo "$latency_result" | sort --reverse --numeric-sort
}

show_servers() {
  # optionally use config: maxlatency, portforwarding
  load_config --ignore-error
  get_serverlist_json
  filter_pf="$(get_filter_pf)"
  filter_protocol="$(get_filter_protocol)"
  # filter for jq
  f='.regions[] '"$filter_pf"' | "\(.servers.meta[0].ip) country=\(.country);'
  f="$f"' region=\(.id) # \(.name);;"+([.servers | to_entries[]'
  f="$f $filter_protocol"' | "  protocol=\(.key);'
  f="$f"' server_ip=\(.value[0] | .ip); server_name=\(.value[0] | .cn)"'
  f="$f"'] | join(";;"))'
  trace "show_servers: jq filter = $f"
  ip_servers_list="$(echo "$serverlist_json" | jq --raw-output "$f")"
  trace "show_servers: ip_servers_list = $ip_servers_list"
  latency_result="$(parallel_tcp_ping "$ip_servers_list")"
  trace "show_servers: latency result:"
  echo "$latency_result" | sort --reverse --numeric-sort | sed 's/$/\n/' | sed 's/;;/\n/g' | sed 's/protocol=wg/protocol=wireguard/' | sed -E 's/protocol=ovpn(tcp|udp)/protocol=openvpn; openvpn_protocol=\1/'
  [ -z "$protocol" ] && info2 "to filter by protocol, in $config_file set protocol=wireguard or protocol=openvpn"
  [ -z "$protocol" ] && info2 "to filter by portforwarding, in $config_file set portforwarding=true or portforwarding=false"
}


log() { echo "$@"; }
info() { echo "${GREEN}INFO${NC} $@"; }
info2() { echo "${GREEN}INFO${NC} $@" >&2; } # print to stderr
success() { echo "${GREEN}SUCCESS${NC} $@"; }
success2() { echo "${GREEN}SUCCESS${NC} $@" >&2; }
warn() { echo "${YELLOW}WARNING${NC} $@"; }
error() { echo "${RED}ERROR${NC} $@"; }
fatal() { echo "${RED}FATAL${NC} $@"; exit 1; }
debug() { $show_debug && echo "${CYAN}DEBUG${NC} $@"; }
debug2() { $show_debug && echo "${CYAN}DEBUG${NC} $@" >&2; } # print to stderr
trace() { $show_trace && echo "${MAGENTA}TRACE${NC} $@"; }
trace2() { $show_trace && echo "${MAGENTA}TRACE${NC} $@" >&2; } # print to stderr

# Only allow script to run as
[ "$(id -u)" = '0' ] || fatal "need root privileges. please run: sudo $script_name"

sample_config="$(cat <<EOF
# piavpn.config.sh

username=p1234567
password=your_password

# optional settings
#protocol=wireguard
#portforwarding=false
#forcedns=true
#maxlatency=50 # milliseconds. maximum latency to auto-select server
#colorterm=true
#loglevel=info # values: info debug trace

# manually choose region or server
#region= # region name. run: $script_name regions
#server_ip= # server address. run: $script_name servers
#server_name=

# optional wireguard settings
#wireguard_disableipv6=true
EOF
)"

show_help() {
cat <<EOF
usage:
$script_name [--config CONFIG] command

commands:
  connect --> connect to VPN server
  regions --> show regions, sorted by latency
  servers --> show servers, sorted by latency

options:
  --config CONFIG --> use CONFIG as config file
                      default: ${default_config_file}

EOF
}

has_cmd() {
  cmd="$1"
  which "$cmd" &>/dev/null
}

get_editor_cmd() {
  [ -z "$EDITOR" ] || { echo "$EDITOR"; return; }
  # nano editor is easier for beginners
  has_cmd nano && { echo nano; return; }
  echo vi
}

load_config() {

  maxlatency="$default_maxlatency"

  if [ ! -f "$config_file" ]; then
    if [ "$1" != '--ignore-error' ]; then
      info "creating a sample config file in $config_file"
      log "please edit that file with"
      log "  $(get_editor_cmd) $config_file"
      log "and run $script_name again"
      echo "$sample_config" >"$config_file"
      exit 1
    fi
  else
    # default values
    #on_new_port() {}
    # . = dot in posix shell = source in bash
    . "$config_file" || fatal "could not load config file '$config_file'"
  fi

  # derive config values
  maxlatency_sec=$(echo "$maxlatency" | awk '{print $1 / 1000}')
  [ "$loglevel" = 'debug' ] && { show_debug=true; }
  [ "$loglevel" = 'trace' ] && { show_debug=true; show_trace=true; }

  if [ "$1" != '--ignore-error' ]; then
    # validate config
    [ -z "$username" ] && fatal 'please set config username, for example username=p1234567'
    [ -z "$password" ] && fatal 'please set config password, for example password=your_password'
  fi
}

# Erase previous authentication token if present
#rm -f /opt/piavpn-manual/token /opt/piavpn-manual/latencyList
# todo: recycle old token if not expired

#curl='curl --no-progress-meter' # make curl less verbose, but still show errors
curl='curl' # openwrt curl has no '--no-progress-meter'

json_get() {
  json="$1"; filter="$2"
  echo "$json" | jq --raw-output "$filter"
}

json_is() {
  json="$1"; filter="$2"; expected="$3"
  actual=$(json_get "$json" "$filter")
  [ "$expected" = "$actual" ] # todo explicit return?
}

date_format='%Y-%m-%dT%H:%M:%SZ%z'

do_login() {
  url_login='https://privateinternetaccess.com/gtoken/generateToken'
  info 'Login ...'
  json="$($curl -u "$username:$password" "$url_login")"
  json_is "$json" .status OK || fatal "login failed. server response: $json"
  export login_token="$(json_get "$json" .token)" login_expires=$(date +"$date_format" --date=+24hours)
  # FIXME openwrt: date: invalid date '+24hours'
  debug "login_token = $login_token"
  success "Login done, expires $login_expires"
}

enable_colors() {
  [ -t 1 ] || return # no terminal (stdout is pipe)
  [ "0$(tput colors 2>/dev/null)" -lt 8 ] && return # no color support
  # FIXME openwrt: tput: not found
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; CYAN='\033[0;36m'
  NC='\033[0m' # No Color
}

# keys for sysctl
ipv6_off1='net.ipv6.conf.all.disable_ipv6'
ipv6_off2='net.ipv6.conf.default.disable_ipv6'

disable_ipv6() {
  sysctl -w ${ipv6_off1}=1 ${ipv6_off2}=1 >/dev/null
  success "IPv6 is now disabled for better security. To enable IPv6 again, run: sysctl -w ${ipv6_off1}=0 ${ipv6_off2}=0"
}

check_ipv6() {
  if [ '11' != "$(sysctl -nb $ipv6_off1 $ipv6_off2)" ]; then
    warn 'IPv6 is enabled. This is a security risk.'
    log "To disable IPv6, add to $config_file:"
    log "  disableipv6=true"
  fi
}

serverlist_url='https://serverlist.piaservers.net/vpninfo/servers/v4'

get_serverlist_json() {
  serverlist_raw=$($curl "$serverlist_url")
  #debug get_serverlist_json: received $(echo "$serverlist_raw" | wc -l) lines
  [ $(echo "$serverlist_raw" | wc -l) = 0 ] && fatal "received partial serverlist from $serverlist_url"
  serverlist_json="$(echo "$serverlist_raw" | head -n1)"
  serverlist_sig="$(echo "$serverlist_raw" | tail -n+3)"
  debug get_serverlist_json: received $(json_get "$serverlist_json" '.regions | length') regions
  trace "get_serverlist_json: serverlist_json = $serverlist_json"

  # verification is redundant since we download from HTTPS server
  #verify_serverlist
}

# https://github.com/pia-foss/desktop/blob/master/daemon/src/environment.cpp#L31
# https://github.com/pia-foss/manual-connections/issues/21
serverlist_pubkey="$(cat <<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzLYHwX5Ug/oUObZ5eH5P
rEwmfj4E/YEfSKLgFSsyRGGsVmmjiXBmSbX2s3xbj/ofuvYtkMkP/VPFHy9E/8ox
Y+cRjPzydxz46LPY7jpEw1NHZjOyTeUero5e1nkLhiQqO/cMVYmUnuVcuFfZyZvc
8Apx5fBrIp2oWpF/G9tpUZfUUJaaHiXDtuYP8o8VhYtyjuUu3h7rkQFoMxvuoOFH
6nkc0VQmBsHvCfq4T9v8gyiBtQRy543leapTBMT34mxVIQ4ReGLPVit/6sNLoGLb
gSnGe9Bk/a5V/5vlqeemWF0hgoRtUxMtU1hFbe7e8tSq1j+mu0SHMyKHiHd+OsmU
IQIDAQAB
-----END PUBLIC KEY-----
EOF
)"

tempfile() {
  filename="${1:-temp}"
  template="${TMPDIR:-/tmp}/piavpn.${filename}.XXXXXX"
  mktemp "$template"
}

verify_serverlist() {
  serverlist_json_file=$(tempfile serverlist.json)
  serverlist_sig_file=$(tempfile serverlist.json.sig)
  serverlist_pubkey_file=$(tempfile serverlist.json.pubkey)
  printf '%s' "$serverlist_json" >"$serverlist_json_file" # no newline
  echo "$serverlist_sig" | base64 -d >"$serverlist_sig_file"
  echo "$serverlist_pubkey" >"$serverlist_pubkey_file"

  res=$(openssl dgst -sha256 \
    -verify "$serverlist_pubkey_file" \
    -signature "$serverlist_sig_file" \
    "$serverlist_json_file") \
  || fatal "could not verify serverlist $serverlist_json_file: $res"

  rm -f -- "$serverlist_json_file" "$serverlist_sig_file" "$serverlist_pubkey_file"
}

connect_to_server() {
  # protocol: default wireguard
  [ "$protocol" = 'openvpn' ] && { connect_to_openvpn; return; }
  connect_to_wireguard
}

# default values. change in config file
default_config_file='/etc/piavpn.config.sh'
config_file="$default_config_file"
datetime_format='%F %T %z'
loglevel='info' # values: info debug trace
show_debug=false
show_trace=false
default_maxlatency=200 # millisec
api_certfile='ca.rsa.4096.crt'
script_name="$0"
server_name=''
server_ip=''
region=''

main "$@"
