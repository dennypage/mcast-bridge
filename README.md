# mcast-bridge

**mcast-bridge is a daemon for forwarding multicast data between
network interfaces. It is intended for use by systems such as
firewalls to provide local bridging of multicast UDP, for both
IPv4 and IPv6.**

---

### The Command Line

The command line usage for mcast-bridge is:

```
mcast-bridge [-h] [-f] [-s] [-c config_file] [-p pid_file] [-Q IGMP_querier_mode] [-M MLD_querier_mode] [-D debug_level]

    -h   Display usage
    -f   Run in the foreground                  (default is to self-background)
    -s   Log notifications via syslog           (default stderr)
    -c   Configuration file to use              (default mcast-bridge.conf)
    -p   Process ID filename                    (default none)
    -I   IGMP querier mode                      (default "quick")
    -M   MLD querier mode                       (default "quick")
    -D   Debug level                            (default none)


    Available IGMP/MLD querier modes:
      never  Never become a querier
      quick  Become a querier immediately at startup (default, RFC behavior)
      delay  Become a querier after 125 seconds if no other querier has been seen
      defer  Become a querier after 125 seconds if no other querier has been seen
             and always defer to any other queriers that may appear regardless of
             relative IP address
```

##### Example:

```mcast-bridge -s -c /etc/mcast-bridge.conf -p /var/run/mcast-bridge.pid```

---

### Configuration File Format

The configuration file for mcast-bridge is an ini styled file, containing
a section for each bridge instance.

Each section in the configuration file defines an independent bridge
instance operating on the UDP port specified.

Each section specifies the multicast group addresses that will be used
for the bridge instance. An instance may have a multicast group address
for IPv4, IPv6, or both. At least one multicast group address is required.

Each section specifies the list of inbound and outbound interfaces that
the bridge instance will operate on. The inbound interface list defines
interfaces that the bridge will receive UDP packets from, and the outbound
interface list defines interfaces that UDP packets will be forwarded to.
An interface may be bidirectional (used for both inbound and outbound).

Optionally, a section may specify a list of inbound or outbound interfaces
to be considered as static interfaces for the bridge instance.

When an inbound interface is declared as static, mcast-bridge will join
the multicast group address for that bridge instance immediately on
startup, rather than waiting for an active subscriber.

When an outbound interface is declared as static, IGMP/MLD will not be
enabled for the interface on that bridge instance, and mcast-bridge will
consider an active subscriber to always be present on the interface.

#### Example bridge section for UDP port 7500:

```
[7500]
    ipv4_address = 239.0.75.0
    ipv6_address = ff05:0:0:0:0:0:0:7500

    inbound_interfaces = igc0, igc1, igc2
    outbound_interfaces = igc0, igc1, igc2

    static_inbound_interfaces = igc1
    static_outbound_interfaces = igc2
```

#### The following properties may be defined in an bridge section:

* `ipv4-address`: The IPv4 multicast address that the bridge instance will
  operate on. Only one IPv4 multicast address per bridge instance may be
  defined.
* `ipv6-address`: The IPv6 multicast address that the bridge instance will
  operate on. Only one IPv6 multicast address per bridge instance may be
  defined.
* `inbound-interfaces`: The list of interfaces that the bridge will receive
  UDP packets from.
* `outbound-interfaces`: The list of interfaces that the bridge will send
  UDP packets to.
* `static-inbound-interfaces`: The list of inbound interfaces that the
  bridge will consider to be static. A static inbound interface is
  automatically considered to be part of the inbound interface list, and
  may or may not be listed separately in `inbound-interfaces`.
* `static-outbound-interfaces`: The list of outbound interfaces that the
  bridge will consider to be static. A static outbound interface is
  automatically considered to be part of the outbound interface list, and
  may or may not be listed separately in `outbound-interfaces`.

---

### Static vs Dynamic for Outbound interfaces

Outbound interfaces that are not declared as static are considered to be
dynamic interest interfaces and mcast-bridge only forwards UDP packets to
those interfaces when a listener is actually present on the interface.

To manage dynamic interest, mcast-bridge implements the following protocols:
* IPv4: IGMP (Internet Group Membership Protocol)
* IPv6: MLD (Multicast Listener Discovery)

See additional notes on the IGMP and MLD implementations below for additional
information.


Things to keep in mind when choosing between static and dynamic interest:
* If a listener is expected to always be present on a bridge interface,
  there is no advantage to using dynamic interest for that interface.
  Declare the interface as static to reduce overhead, both packets and
  CPU from running the dynamic protocols.
* If the switch in use has IGMP or MLD snooping enabled, additional
  configuration will be required for the port(s) that mcast-bridge is
  connected to. In particular, the port(s) need to be configured as a
  Multicast Router Port for IGMP and/or MLD. How to do this is far
  outside the scope of this README. See your switch documentation.
* If dynamic interest seems to work initially, and then stops after a
  while, it is likely that a switch or router has disabled the necessary
  multicast control groups on the port(s). Check the switch or router
  Multicast Router Port configuration again.
* If you run into problems with dynamic interest, use static.

---

### Static vs Dynamic for Inbound interfaces

Inbound interfaces that are declared as static join the multicast group
immediately on startup, whereas dynamic interfaces will not join the
multicast group until a listener appears on one of the other interfaces
in the bridge.

Things to keep in mind regarding static vs dynamic inbound interfaces:
* Static bridge interfaces will have slightly less initial latency when
  a listener joins, both from the host on which mcast-bridge is running, and
  from the switch mcast-bridge is connected to if IGMP or MLD snooping is
  enabled on the switch.
* Static bridge interfaces will always receive and process packets when no
  listener is actually present. Use of dynamic avoids this CPU and packet
  overhead. Unless the first packet is critical to the listener, declaring an
  inbound interface as static is probably not necessary.
* If an outbound interface is declared as static, there is no need to declare
  the associated inbound interfaces as static (this is handled automatically).

---

### Notes on the IGMP and MLD implementations

The IGMP implementation is based on RFC 2236 and RFC 9976,
while the MLD implementation is based on RFC 2236 and RFC 9976.

The implementations deviate from the standards in the following aspects:

1. The implementations ignore all link-local scope multicast addresses:
   * IPv4: 224.0.0.0/24
   * IPv6: ff02::/16
2. The IGMPv3 and MLDv2 implementations work at the IP group level only, ignoring
   all source specific address information. This is similar to some switches or
   routers with the forwarding method set to "IP Group Address" instead of
   "Source Specific IP Group Address".
3. The implementations offer multiple querier modes. One of these modes, "quick",
   corresponds to the RFC specified behaviors. The other modes are extensions or
   alterations of the RFC behavior. See below for additional information on the
   available querier modes.
5. The implementations allow a few milliseconds of grace time for protocol
   timeouts to allow for network round trip and host processing time.

#### Notes On Querier Modes

The implementations offers multiple querier modes:
* never: The querier function is completely disabled. With this mode, mcast-bridge
         is completely passive and dependant on another querier being present.
         This mode is appropriate to use with switches that are performing IGMP
         or MLD snooping.
* quick: The querier function is activated immediately at startup. This mode is the
         default, and corresponds to the RFC specified behavior.
* delay: The querier function will be activated after 125 seconds if no other querier
         has been seen. After the querier function has been activated, the querier
         behaves per the RFC specified behavior, including participating in querier
         elections.
* defer: The querier function will be activated after 125 seconds if no other querier
         has been seen. If any other querier is seen, the querier function will
         deactivate, deferring to the new querier regardless of relative IP addresses.
         This behavior corresponds to some switches or routers with a "Querier
         Election Disabled" option.

Things to keep in mind regarding the querier function:
* The querier function is only use on dynamic interest interfaces. If a bridge
  interface is declared as static, the querier function is not used on that
  interface.
* As a querier mcast-bridge can only track a limited number of groups. mcast-bridge
  tracks all groups that have been explicitly configured as part of a bridge, and
  up to 100 additional groups per interface. If you have a large network with
  more than 100 active multicast groups, a switch or router should be used as the
  active querier and the mcast-bridge querier option should be set to "never".
* When used with a switch that has IGMP or MLD snooping enabled, all querier modes
  require the port(s) used for mcaast-bridge to be configured as Multicast Router
  Ports. If the querier function seems to work initially, and then stops after a
  while, it is likely that a switch or router has disabled the necessary multicast
  control groups on the port(s) mcast-bridge is attached to. Check the switch
  Multicast Router Port configuration.
* Configuration details of various multicast enabled switches or routers vary
  wildly, and often are not for the faint of heart. Assistance on the configuration
  of specific switches or routers is far outside the scope of this probject, so
  please don't ask. If you run into difficulty configuring a multicast switch, save
  yourself, and everyone around you, a lot of grief by using a static interface.


---

### The mcast-bridge test program (mcb-test)

The mcast-bridge distribution includes a simple test program, mcb-test, that may
be used to confirm multicast connectivity between segments.

The command line usage for mcb-test is:

```
mcb-test [-4|-6] [-n] [-s] [-i interface] [-p port] [multicast address]

  options:
    -h               Display usage
    -4               Use IP version 4             (default)
    -6               Use IP version 6
    -n               Show numeric hostnames       (default is to resolve hostnames)
    -s               Sender mode                  (default is receiver mode)
    -i               Interface to use             (default is the system default interface)
    -p               UDP port                     (default is 7500)

  the default multicast address for IP version 4 is 239.0.75.0
  the default multicast address for IP version 6 is ff05::7500
```
