// Proxmox API fixture routes (shapes per the PVE API: every body is {data}).
export const T = 1_800_000_000; // node clock, seconds
const log = (lines) => lines.map((t, i) => ({ n: i + 1, t }));
export function proxmoxRoutes(over = {}) {
  const d = (data) => ({ data });
  return {
    "/api2/json/cluster/status": d([{ type: "cluster", name: "homelab" }, { type: "node", name: "norco", ip: "192.168.0.10", online: 1 }, { type: "node", name: "main", ip: "192.168.0.4", online: 1 }]),
    "/api2/json/cluster/resources": d([
      { vmid: 109, name: "docker", node: "norco", type: "qemu", status: "running" },
      { vmid: 114, name: "ollama", node: "norco", type: "lxc", status: "running" },
      { vmid: 100, name: "jelly-arr", node: "main", type: "qemu", status: "running" }
    ]),
    "/api2/json/nodes/norco/qemu/109/config": d({ net0: "virtio=BC:24:11:AA:00:01,bridge=vmbr0,firewall=1" }),
    "/api2/json/nodes/norco/lxc/114/config": d({ net0: "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:AA:00:02,ip=192.168.0.114/24,type=veth" }),
    "/api2/json/nodes/main/qemu/100/config": d({ net0: "virtio=BC:24:11:AA:00:03,bridge=vmbr0" }),
    "/api2/json/nodes/norco/time": d({ time: T, localtime: T, timezone: "America/New_York" }),
    "/api2/json/nodes/main/time": d({ time: T + 7, localtime: T + 7, timezone: "America/New_York" }),
    "/api2/json/nodes/norco/disks/list": d([{ devpath: "/dev/nvme0n1", model: "Samsung", health: "PASSED", wearout: 97, type: "nvme" }]),
    "/api2/json/nodes/main/disks/list": d([{ devpath: "/dev/sda", model: "WD", health: "PASSED", wearout: "N/A", type: "hdd" }]),
    "/api2/json/nodes/norco/storage": d([{ storage: "backups", active: 1, enabled: 1, used: 100, total: 1000, shared: 1 }]),
    "/api2/json/nodes/main/storage": d([{ storage: "backups", active: 1, enabled: 1, used: 100, total: 1000, shared: 1 }]),
    "/api2/json/cluster/backup": d([{ id: "daily", enabled: 1, all: 1, exclude: "114", storage: "backups" }]),
    // A PVEAuditor token sees an empty backup listing (Proxmox hides backup
    // volumes without Datastore.AllocateSpace + VM.Backup).
    "/api2/json/nodes/norco/storage/backups/content": d([]),
    "/api2/json/nodes/main/storage/backups/content": d([]),
    "/api2/json/nodes/norco/tasks": d([
      { upid: "UPID:norco:0001:vzdump::root@pam:", type: "vzdump", id: "", status: "OK", endtime: T - 3600 },
      { upid: "UPID:norco:0002:vzdump::root@pam:", type: "vzdump", id: "", status: "job errors", endtime: T - 90000 }
    ]),
    [`/api2/json/nodes/norco/tasks/${encodeURIComponent("UPID:norco:0001:vzdump::root@pam:")}/log`]: d(log([
      "INFO: starting new backup job: vzdump --all 1 --exclude 114 --storage backups",
      "INFO: Starting Backup of VM 109 (qemu)",
      "INFO: Finished Backup of VM 109 (00:01:02)",
      "INFO: Backup job finished successfully"
    ])),
    [`/api2/json/nodes/norco/tasks/${encodeURIComponent("UPID:norco:0002:vzdump::root@pam:")}/log`]: d(log([
      "INFO: Starting Backup of VM 109 (qemu)",
      "ERROR: Backup of VM 109 failed - timeout"
    ])),
    "/api2/json/nodes/main/tasks": d([{ upid: "UPID:main:0003:vzdump::root@pam:", type: "vzdump", id: "", status: "job errors", endtime: T - 7000 }]),
    [`/api2/json/nodes/main/tasks/${encodeURIComponent("UPID:main:0003:vzdump::root@pam:")}/log`]: d(log([
      "INFO: Starting Backup of VM 100 (qemu)",
      "ERROR: Backup of VM 100 failed - no space left on device"
    ])),
    ...over
  };
}
