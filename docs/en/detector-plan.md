# Detector Plan

The detector is the second half of the agent: it consumes sampled packet
metadata and VPP counters, maintains bounded state, and emits synthetic
FlowSpec-style drop rules that can be fed into the existing manager.

## Goal

- Keep the existing BGP FlowSpec -> translate -> VPP ACL path unchanged.
- Add a fixed-memory detector that can load YAML rules and compile them into
  fast matchers.
- Treat detection metadata (TTL, ingress interface, observed rate, description)
  as local event data, outside the FlowSpec rule model.
- Consume sFlow v5 raw packet headers into `detector.Sample`, poll VPP interface
  counters into fixed rings, and wire `detector.Event` into the existing manager
  as local synthetic FlowSpec updates.

## Capacity Budget

Expected defaults:

- interfaces: around 10
- rules: <= 100
- instances per rule: <= 100
- sampled rate: usually <= 20 kpps, worst case around 150 kpps
- memory target: below 1 GiB

Stats ring proposal:

- 30 days at 5 minute resolution: 8,640 slots/interface
- 7 days at 1 minute resolution: 10,080 slots/interface
- 1 day at 5 second resolution: 17,280 slots/interface
- total: 36,000 slots/interface

At 48-64 bytes per interface slot this is roughly 17-23 MiB for 10 interfaces.

Rule instance ring proposal:

- 7 days at 1 hour resolution: 168 slots
- 1 day at 1 minute resolution: 1,440 slots
- 10 minutes at 1 second resolution: 600 slots
- total: 2,208 slots/instance

At 16 bytes per slot this is about 34.5 KiB per instance, or around 337 MiB for
10,000 instances. The detector stores the configured hot/day/week rings per
instance, capped by `history.max_instances` per rule.

## Rule Shape

Example:

```yaml
rules:
  - name: udp-small-flood
    match:                       # filter only (ranges/sets allowed; packet_len never emitted)
      family: ipv4
      proto: udp
      packet_len: { lt: 100 }
    aggregate:                   # descriptor granularity = instance identity
      src: "/24"
    history:
      fine:  { resolution: 1s, duration: 10m }
      medium:  { resolution: 1m, duration: 1d }
      coarse: { resolution: 1h, duration: 7d }
      max_instances: 200
    trigger:
      terms:
        short: { metric: pps, window: 10s }
        base:  { metric: pps, window: 10m, offset: 1m }
      expr: "short > 5 * base and short > 100000"
      sustained: 20s
    flowspec:                    # each field defaults to the descriptor value
      action: drop
      ttl: 300s
      refresh: true
    description: "udp flood from {{src}}, pps={{short}}"
```

The model evolved from the original sketch above: `group_by` was replaced by
`aggregate` (granularity that defines the descriptor, which *is* the instance
identity), and the fixed `window/consecutive/op/value` trigger became named
`terms` plus a free-form `expr` evaluated on a periodic tick. See
`docs/en/configuration.md` for the authoritative reference.

## Implementation Stages

1. Compile YAML detector rules into fixed structures. Done.
2. Maintain fixed-capacity per-rule instance state keyed by descriptor. Done.
3. Fold samples into rings on the hot path; evaluate triggers on a tick. Done.
4. Emit local events with synthetic `flowspec.Rule` payloads. Done.
5. Add sFlow collector and VPP stats reader. Done for sFlow v5 raw packet
   headers and VPP interface counters.
6. Add lease controller to announce/refresh/withdraw local rules through the
   existing manager. Done using the `detector` synthetic session.
7. Load rules from embedded predefined files plus a runtime directory, selected
   by `rules_enabled`. Done.
8. Expression triggers over named windowed terms via `expr-lang/expr`. Done.
9. Future work: expose detector/VPP-stats metrics, add richer match/aggregate
   fields (TCP flags, ICMP type/code), and let terms read rollups by name.
