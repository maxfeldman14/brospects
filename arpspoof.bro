##! Analysis of ARP Spoofing Traffic.
##! This script logs ARP traffic while doing so builds an internal ARP cache
##! that can be used to determine when MAC/IP associations change.
#
# Abbreviations are taken from RFC 826:
#
# SHA: source hardware address (i.e., MAC address)
# SPA: source protocol address (i.e., IP address)
# THA: target hardware address
# TPA: target protocol address

@load base/frameworks/notice

module ARPSPOOF;

export {
      redef enum Log::ID += { LOG };

      redef enum Notice::Type += {
              Unsolicited_Reply                # It could be poisoning; or just gratuitous
      };

      # TODO: collect the information from the arp.bro script
      # instead of collecting it manually.
      # Possible types of spoofing:
      # gratuitous arp replies
      # spoofed claimed IP in who_has
      # spoofed mac with real IP in who_has
      # TODO: check claimed IP and mac against DHCP
      # TODO: see if a spoofer is sending many who_has requests
      # with the same information
      type Info: record {
              ## All the logging info
              ts:                time;              #  &log;
              ## The requestor's MAC address.
              src_mac:        string;              #  &log &optional;
              ## The requestor's IP address, if known. This is populated based
              ## on ARP traffic seen to this point.
              src_addr:        addr;              #  &log &optional;
              ## The responder's MAC address.
              dst_mac:        string;              #  &log &optional;
              ## The responder's IP address, if known. This is populated based
              ## on ARP traffic seen to this point.
              dst_addr:        addr;              #  &log &optional;
              ## Flag to indicate that a response was unsolicited
              unsolicited:        bool;             #  &log &default=F;
              ## Flag to indicate that a response was never received
              no_resp:        bool;              #  &log &default=F;
              ## The IP address that is requested in the ARP request
              who_has:        addr;              #  &log &optional;
              ## The assocaited MAC address from the ARP response
              is_at:                string;              #  &log &optional;
      };

      type Spoofer: record {
              ## The MAC address of the host spoofing replies
              sender_mac:        string        &log;
              ## The number of unsolicited replies this sender sent
              replies_count:        count        &log &default=0;
              ## Has this sender changed a prior addr->MAC mapping?
              changed_mapping:        bool        &log &default=F;
              ## Does this sender have multiple IPs associated with its MAC?
              multiple_ips:        bool        &log &default=F;
              ## Has the spoofer claimed (via ARP) an IP address not 
              ## assigned by DHCP?
              claimed_non_DHCP:        bool        &log &default=F;
              ## Has the spoofer sent multiple "WHO HAS"s with the
              ## same information?
              many_who_has:        bool        &log &default=T;
              ## The IP(s) which this host has claimed
              ips:        set[addr]        &log;
              ## The victim IP(s) to which a host has spoofed
              victims:        set[addr]     &log;
              
      };



      global log_arp: event(rec: Spoofer);
}

redef capture_filters += { ["arp"] = "arp" };

global expired_request: function(t: table[string, addr, addr] of Info, idx: any): interval &redef;

type State: record {
      mac_addr:        string;
      ip_addr:        addr;
      assoc_ips:        set[addr];
      requests:        table[string, addr, addr] of Info
                          &create_expire = 1 min
                          &expire_func = expired_request;
};
global arp_states: table[string] of State;

# Unsolicited replies will hold all unsolicited replies from all hosts.
# Lookup a spoofer by its source addr.
global spoofers: table[string] of Spoofer;

# ARP responses we've seen: indexed by IP address, yielding MAC address.
global ARP_cache: table[addr] of string;

# A somewhat general notion of broadcast MAC/IP addresses.
const broadcast_mac_addrs = { "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", };
const broadcast_addrs = { 0.0.0.0, 255.255.255.255, };

# Create a new arp_request record with the given src and dst fields.
function new_arp_request(mac_src: string, mac_dst: string): Info
      {
      local request: Info;
      request$ts = network_time();
      request$src_mac = mac_src;
      request$dst_mac = mac_dst;

      return request;
      }

# Create a new Spoofer record.
function new_spoofer(mac_src: string, claimed: addr, vic: addr, changed_mapping: bool): Spoofer
      {
      local spoofer: Spoofer;
      spoofer$sender_mac = mac_src;
      # On creation the spoofer has only spoofed once.
      spoofer$replies_count = 1;
      spoofer$changed_mapping = changed_mapping;
      # One instance of spoofing means that only one
      # IP has been claimed. Add it to the set, and
      # set the multiple flag to false.
      spoofer$ips = set(claimed);
      spoofer$victims = set(vic);
      spoofer$multiple_ips = F;

      return spoofer;
      }

# Create a new state record for the given MAC address.
function new_arp_state(mac_addr: string): State
      {
      local state: State;
      state$mac_addr = mac_addr;

      return state;
      }

# Returns the IP address associated with a MAC address, if we've seen one,
# otherwise just returns the MAC address.
function addr_from_mac(mac_addr: string): string
      {
      return mac_addr in arp_states ?
              fmt("%s", arp_states[mac_addr]$ip_addr) : mac_addr;
      }

# Completes an Info record by populating the src and dst IP addresses, if
# known, and logs the ARP traffic via the Log framework.
function log_request(rec: Info)
      {
      if ( rec$src_mac in arp_states )
              rec$src_addr = arp_states[rec$src_mac]$ip_addr;

      if ( rec$dst_mac in arp_states )
              rec$dst_addr = arp_states[rec$dst_mac]$ip_addr;

      }

# Expiration function which is called when a ARP request does not receive
# a valid response within the expiration timeout period.
function expired_request(t: table[string, addr, addr] of Info, idx: any): interval
      {
      local SHA: string;
      local SPA: addr;
      local TPA: addr;

      [SHA, SPA, TPA] = idx;
      local request = t[SHA, SPA, TPA];
      request$no_resp = T;

      log_request(request);

      return 0 sec;
      }

# Create association between MAC address and an IP address. This is *not* an
# association advertised in an ARP reply (those are tracked in ARP_cache), but
# instead the pairing of hardware address + protocol address as expressed in
# an ARP request or reply header.
function mac_addr_association(mac_addr: string, a: addr)
      {

      # Ignore broadcast and network addresses (IP and Ethernet).
      if ( mac_addr in broadcast_mac_addrs || a in broadcast_addrs )
              return;

      # Get state record.
      if ( mac_addr !in arp_states )
              arp_states[mac_addr] = new_arp_state(mac_addr);
      local arp_state = arp_states[mac_addr];

      arp_state$ip_addr = a;
      add arp_state$assoc_ips[a];

      }

event bro_init() &priority=5
      {
      Log::create_stream(ARPSPOOF::LOG, [$columns=Spoofer, $ev=log_arp]);
      }

event bro_done() &priority=5
      {
      print "reached done";
      for (spfer in spoofers) {
        Log::write(ARPSPOOF::LOG, spoofers[spfer]);
        }
      }

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
      {
      mac_addr_association(SHA, SPA);

      local arp_state: State;
      arp_state = arp_states[SHA];

      # Check that ethernet src and arp src are the same
      local mismatch = SHA != mac_src;

      # Create new ARP request and store in state record
      local request = new_arp_request(mac_src, mac_dst);
      request$who_has = TPA;

      # Check reply against current ARP_cache
      local mapping_changed = SPA in ARP_cache && ARP_cache[SPA] != SHA;

      # Check requests to see if this same request has
      # been sent in the past minute, which may indicate
      # an attack

      if [SHA, SPA, TPA] in arp_state$requests {
        # May be an attack, so find or create a spoofer
        local spoofer: Spoofer;
        if ( mac_src in spoofers ) {
            spoofer = spoofers[mac_src];
            add spoofer$ips[SPA];
            add spoofer$victims[TPA];
            spoofer$replies_count += 1;
            spoofer$changed_mapping = T;
        }
        else {
            spoofer = new_spoofer(mac_src, SPA, TPA, mapping_changed);
        }

      }
      arp_state$requests[SHA, SPA, TPA] = request;
      }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
      {
      mac_addr_association(SHA, SPA);
      mac_addr_association(THA, TPA);

      local arp_state: State;
      arp_state = arp_states[THA];

      local msg = fmt("%s -> %s: %s is-at %s",
              addr_from_mac(mac_src), addr_from_mac(mac_dst), SPA, SHA);

      # Check for source mac mismatch
      # A mismatch could indicate spoofing
      local mismatch = SHA != mac_src;

      # Check reply against current ARP_cache
      local mapping_changed = SPA in ARP_cache && ARP_cache[SPA] != SHA;

      # Check if reply is unsolicited and get request record
      # An unsolicited reply could indicate spoofing

      # An unsolicited reply which causes a mismatch could indicate
      # the beginning of a spoofing attack

      # Multiple unsolicited replies from the same host are a stronger
      # indicator of an arp spoofing attack (especially many in rapid 
      # succession)

      local request: Info;
      if ( [THA, TPA, SPA] !in arp_state$requests ) {
              request = new_arp_request(THA, SHA);
              request$unsolicited = T;

              # SHA is the ARP packet's mac addr of the sender
              # mac_src is the ethernet packet's mac
              # SHA is the "actual" address of the sender, 
              # TODO: is it actually mac_src?
              #   may need to switch sha and mac_src
              # TODO: check if the above is true
              # Increment count else, create it

              local spoofer: Spoofer;
              if ( mac_src in spoofers ) {
                  spoofer = spoofers[mac_src];
                  add spoofer$ips[SPA];
                  add spoofer$victims[TPA];
                  spoofer$replies_count += 1;
                  spoofer$changed_mapping = T;
              }
              else {
                  spoofer = new_spoofer(mac_src, SPA, TPA, mapping_changed);
              }

              # Add the spoofer to spoofers.
              spoofers[mac_src] = spoofer;

      } else {
              request = arp_state$requests[THA, TPA, SPA];
              delete arp_state$requests[THA, TPA, SPA];
      }
      

      request$is_at = SHA;
      log_request(request);

      ARP_cache[SPA] = SHA;
      }
