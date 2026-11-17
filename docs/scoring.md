# Posture score (rules version 1)

The score is a number from 0 to 100 computed from vulnerability findings. It
is published as two numbers, because some of what feeds it is certain and some
is not:

> `<confirmed> based on confirmed findings; <pessimistic> in the pessimistic case`

- **Confirmed** counts only what the engine has established.
- **Pessimistic** assumes every open question goes the wrong way: an unknown
  exposure is public, an unverified gate isn't a gate, an out-of-date KEV list
  would have listed the CVE, and a package that *looks like* the one serving a
  public route really is.

The pessimistic number is never higher than the confirmed one. The gap between
them is how much of the picture is uncertain.

## What costs points

Each finding is counted once. Low-confidence findings and findings the owner
has accepted cost nothing in either scenario.

| Finding | Points |
|---|---|
| Urgent (see below) | 10 |
| High or critical, fix available but not applied | 3 |
| Medium, fix available but not applied | 0.5 |
| Anything else (low, no fix exists, fix state unknown) | 0 |

In the pessimistic scenario a finding costs 10 if it is urgent, if its urgency
is unknown, or if it is "possibly urgent"; otherwise it costs the same as in
the confirmed scenario. So a finding already costing 3 adds 7 more, not 13.

**Per-machine cap:** one machine can cost at most 25 points in each scenario,
so a single neglected machine can't hide the state of the rest.

**Score** = 100 − (sum over machines of that machine's points, capped at 25),
never below 0.

### Worked example

| Machine | Finding | Confirmed | Pessimistic |
|---|---|---|---|
| A | kernel flaw, actively exploited (urgent) | 10 | 10 |
| A | high, fix available, possibly urgent | 3 | 10 |
| A | medium, fix available | 0.5 | 0.5 |
| B | low, urgency unknown (exposure not established) | 0 | 10 |

Machine A: 13.5 confirmed, 20.5 pessimistic. Machine B: 0 and 10.
Result: **86.5 based on confirmed findings; 69.5 in the pessimistic case**.

## What "urgent" means (urgency rules version 1)

A finding is urgent when its software is:

- internet-facing (the entry proxy, the login gate itself) **and** either
  actively exploited (on the CISA KEV list) or high/critical with a fix
  available; or
- on a machine reachable from the internet (behind a route, behind a login
  gate, or forwarded to directly) **and** actively exploited.

Only exposure established from routes and only verified login gates count.
Missing or out-of-date inputs make urgency *unknown*, never "not urgent".

## When there is no score

The score is `incomplete`, with no numbers, when any of these holds:

- vulnerability findings are out of date or were never read;
- the KEV list is missing or more than 7 days old;
- the exposure map is missing, stale or its last run failed;
- more than 20 % of the machines that should be scanned have no current
  vulnerability scan (no machines in scope counts as incomplete too).

The reasons are listed alongside. A number computed from a partial picture
would look more trustworthy than it is.

## Changing the rules

Any change to the weights, the cap, the thresholds or the urgency rule bumps
the version number, so a score can always be traced to the rules that
produced it. The same evidence always gives the same score.
