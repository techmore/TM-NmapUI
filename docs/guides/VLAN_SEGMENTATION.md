# VLAN detection and segmentation recommendations (#31)

NmapUI reports what its scan data supports about network segmentation, and says
how strongly. It does **not** enumerate switch-level VLAN configuration: a host
scan cannot see that. Implementation: `nmapui/segmentation.py` (analysis),
`nmapui/topology_recommendations.py` (report appendix), and the
`/api/runtime/reports/<scan>/segmentation` route.

## Passive by design

The analysis reads data the scanner already holds. It sends no packets, crafts
no 802.1Q frames, requests no trunk negotiation and attempts no VLAN hopping or
other attack-style probe. A test asserts the module imports no socket,
subprocess or HTTP primitives.

## Evidence it uses

| Source | Signal | Confidence it can support |
| --- | --- | --- |
| Nmap XML script output (host or port scripts) | LLDP/CDP/802.1Q text such as `Port VLAN ID`, `Native VLAN`, `VLAN ID`; DTP / dynamic-trunk mentions | detected |
| Operator-supplied configuration (below) | VLAN list with subnets, trunk native VLAN, allowed-VLAN lists, DTP modes, access-port VLANs | detected (source `supplied`) |
| Traceroute hops (`-A` deep scans) | A router between the scanner and a subnet, with no MAC returned | likely |
| MAC addresses | Nmap returns a MAC only for hosts on the scanner's own broadcast domain; several subnets answering with MACs share one link | likely |
| Hostnames / hop names | `vlan20.core...` naming conventions (end-device names must spell out `vlan`; router interfaces may use `vl20`) | likely, never a VLAN ID |
| Address grouping only | /24 grouping of responding private IPv4 hosts | unverified |

Existing deep scans (`-A -sC`) already produce traceroute and default-script
data. The stock default scripts do not emit LLDP/CDP VLAN IDs, so in practice
`detected` findings come from supplied configuration or from custom/imported
script output.

## Confidence levels

- **detected**: a VLAN identifier or trunk setting is present in the data. Each
  finding's `source` is `observed` (scan output) or `supplied` (configuration,
  which shows intent rather than live state).
- **likely**: several observations agree on a boundary but no VLAN ID was seen.
  Wording is "appears", "suggests"; each finding lists its evidence.
- **unverified**: only subnet grouping, or nothing. The report names the data
  that would settle the question (deep scan, LLDP/CDP table, config export).

No hosts, or hosts that are down, yield no findings and no report section.

## Recommendations

Recommendations are attached to the finding that justifies them and inherit its
confidence, so the report never states more than the evidence allows:

- segmentation: confirm VLAN-to-subnet mapping; check inter-segment ACLs where
  a router path to another subnet was observed; separate subnets that share a
  broadcast domain when isolation is intended;
- native VLAN: move trunks off VLAN 1; keep the native VLAN free of access ports;
- trunk hygiene: prune allowed-VLAN lists; disable DTP negotiation
  (`switchport nonegotiate`, explicit access/trunk modes); keep VLAN 1 unused.

## Supplying a configuration (optional, read-only)

Place either or both files in the scan's folder (beside the saved XML). Each is
capped at 1 MiB; malformed files are ignored.

`l2_evidence.json` (field names follow the Meraki dashboard API):

```json
{
  "source": "Meraki dashboard export 2026-10-01",
  "vlans": [{"id": 10, "name": "Staff", "subnet": "192.168.10.0/24"}],
  "ports": [
    {"portId": "24", "type": "trunk", "vlan": 99, "allowedVlans": "10,20"},
    {"portId": "3", "type": "access", "vlan": 10}
  ]
}
```

`switch_config.txt`: Cisco IOS-style text. `vlan N` / `name`, `interface VlanN`
with `ip address`, and per-interface `switchport mode`, `switchport trunk native
vlan`, `switchport trunk allowed vlan`, `switchport access vlan` and
`switchport nonegotiate` are understood; other lines are ignored. Do not put
credentials or secrets in either file.

## Where it appears

- **Reports tab**: a network icon on each saved report opens the segmentation
  page (`?format=html`); the same route returns JSON by default.
- **Report appendix** (HTML/PDF): a "Segmentation & VLAN observations" section
  follows the topology appendix, when "Include topology recommendations" is on
  for the customer/subnet (existing opt-in setting). The appendix's before/after
  note about VLANs changes from "unverified" only when detected or likely
  evidence exists.

## Limits

Nmap gives no subnet masks, so grouping assumes /24 unless supplied
configuration gives exact subnets. Nothing here proves the absence of VLANs.
The scanner is not assumed to be on a trunk; it does not learn VLAN tags from
frames. Active LLDP/CDP listening, SNMP bridge-MIB reads and direct switch API
queries are out of scope here and would be separate, explicitly approved
features.
