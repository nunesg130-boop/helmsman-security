// Wazuh 4.14 server API fixture routes. Bodies follow the API's
// {data: {affected_items, total_affected_items}} envelope.
export const page = (items, total = items.length) => ({ data: { affected_items: items, total_affected_items: total, failed_items: [], total_failed_items: 0 }, message: "ok", error: 0 });
export const KEEPALIVE = "2026-11-12T11:55:00+00:00";

export function wazuhRoutes(over = {}) {
  return {
    "POST /security/user/authenticate": { data: { token: "jwt-1" }, error: 0 },
    "/agents": page([
      { id: "000", name: "wazuh", ip: "127.0.0.1", status: "active", lastKeepAlive: "9999-12-31T23:59:59+00:00" },
      { id: "001", name: "norco", ip: "192.168.0.10", status: "active", lastKeepAlive: KEEPALIVE },
      { id: "010", name: "legion", ip: "192.168.0.50", status: "disconnected", lastKeepAlive: "2026-11-10T08:00:00+00:00" },
      { id: "011", name: "new-box", ip: "any", status: "never_connected" }
    ]),
    "/syscollector/001/os": page([{ os: { name: "Debian GNU/Linux", version: "12 (bookworm)", major: "12", minor: "8", platform: "debian" }, sysname: "Linux", release: "6.8.12-4-pve", architecture: "x86_64", hostname: "norco" }]),
    "/syscollector/001/packages": page([{ name: "pve-manager", version: "8.2.7", architecture: "amd64", format: "deb" }, { name: "proxmox-kernel-6.8.12-4-pve-signed", version: "6.8.12-4", architecture: "amd64", format: "deb" }]),
    "/syscollector/001/hotfixes": page([]),
    "/syscollector/001/ports": page([{ protocol: "tcp", local: { ip: "0.0.0.0", port: 8006 }, state: "listening", process: "pveproxy", pid: 1234 }]),
    "/syscollector/001/processes": page([{ name: "pveproxy", pid: "1234", euser: "www-data" }]),
    "/syscollector/001/hardware": page([{ cpu: { name: "Intel i5-11600", cores: 6 }, ram: { total: 65536000, free: 20000000 } }]),
    "/syscollector/001/netiface": page([{ name: "vmbr0", mac: "aa:bb:cc:dd:ee:01", type: "ethernet" }, { name: "lo", mac: "00:00:00:00:00:00" }]),
    "/syscollector/000/os": page([{ os: { name: "Ubuntu", major: "24", minor: "04", platform: "ubuntu" }, release: "6.8.0-45-generic" }]),
    "/syscollector/000/packages": page([]),
    "/syscollector/000/hotfixes": page([]),
    "/syscollector/000/ports": page([]),
    "/syscollector/000/processes": page([]),
    "/syscollector/000/hardware": page([]),
    "/syscollector/000/netiface": page([]),
    "/syscollector/010/os": page([{ os: { name: "Fedora Linux", major: "42", minor: "", platform: "fedora" }, release: "6.14.2-300.fc42.x86_64" }]),
    "/syscollector/010/packages": page([{ name: "kernel-core", version: "6.14.2-300.fc42", architecture: "x86_64" }]),
    "/syscollector/010/hotfixes": page([]),
    "/syscollector/010/ports": page([]),
    "/syscollector/010/processes": page([]),
    "/syscollector/010/hardware": page([]),
    "/syscollector/010/netiface": page([{ name: "wlp0s20f3", mac: "aa:bb:cc:dd:ee:10" }]),
    ...over
  };
}
