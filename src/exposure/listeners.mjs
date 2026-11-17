// Is anything actually listening behind a route? A "yes" needs one fresh
// matching row. A "no" needs proof the inventory is whole: a complete, fresh
// port list from an active agent and, where Docker could be publishing the
// port, a complete, fresh container list too. Anything less is "unknown".
import { usable } from "../checks/runner.mjs";

const RUNTIMES = new Set(["docker-ce", "docker.io", "containerd", "containerd.io", "podman"]);
const WILDCARDS = new Set(["0.0.0.0", "::", "*"]);
const proto = (p) => String(p ?? "").toLowerCase().replace(/6$/u, "");

export function listenerEvidence(asset, store, now) {
  const get = (kind) => usable(store, asset, kind, now).ev ?? null;
  const hasAgent = Boolean(asset?.sources?.wazuh?.id);
  const agent = hasAgent ? get("wazuh.agent") : null;
  const portsEv = hasAgent ? get("wazuh.ports") : null;
  const metaEv = hasAgent ? get("wazuh.ports.meta") : null;
  const rows = Array.isArray(portsEv?.value) ? portsEv.value : [];
  const ports = {
    rows,
    fresh: Boolean(portsEv),
    complete: Boolean(portsEv && metaEv && agent?.value?.status === "active" && metaEv.value?.complete === true && metaEv.runId === portsEv.runId
      && metaEv.value.rows === metaEv.value.total && metaEv.value.rows === rows.length && rows.length > 0)
  };

  let dockerHost = "no";
  let containers = null;
  if (asset?.sources?.docker) {
    dockerHost = "configured";
    const listEv = get("docker.containers");
    const listMeta = get("docker.containers.meta");
    const list = Array.isArray(listEv?.value) ? listEv.value : [];
    containers = { rows: list, fresh: Boolean(listEv), complete: Boolean(listEv && listMeta && listMeta.value?.complete === true && listMeta.runId === listEv.runId && listMeta.value.rows === list.length) };
  } else {
    // Without a package list the engine can't rule a container runtime out.
    const packages = hasAgent ? get("wazuh.packages") : null;
    const names = packages?.value?.scanned ? (packages.value.items ?? []).map((p) => String(p.name ?? "").toLowerCase()) : null;
    if (!names || names.some((n) => RUNTIMES.has(n))) dockerHost = "unmonitored";
  }
  return { ports, containers, dockerHost };
}

// { listening: true|false|null, process, container } for one address, port and protocol.
export function listenerMatch({ ip, port, protocol = "tcp" }, evidence) {
  const want = proto(protocol);
  const onAddress = (bound) => bound === ip || WILDCARDS.has(String(bound ?? ""));
  const { ports, containers, dockerHost } = evidence ?? { ports: { rows: [], fresh: false, complete: false }, containers: null, dockerHost: "unmonitored" };

  const row = ports.fresh ? ports.rows.find((r) => proto(r.protocol) === want && Number(r.localPort) === port && onAddress(r.localIp)) : null;
  const publisher = containers?.fresh
    ? containers.rows.find((c) => c.state === "running" && (c.ports ?? []).some((p) => Number(p.publicPort) === port && proto(p.type) === want && onAddress(p.ip)))
    : null;
  if (row || publisher) return { listening: true, process: row?.process ?? null, container: publisher?.name ?? null };

  const socketsRuledOut = ports.fresh && ports.complete;
  const containersRuledOut = dockerHost === "no" || (dockerHost === "configured" && Boolean(containers?.fresh && containers.complete));
  return { listening: socketsRuledOut && containersRuledOut ? false : null, process: null, container: null };
}

export const isListening = (target, evidence) => listenerMatch(target, evidence).listening;
