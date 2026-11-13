// Proxmox API fixture routes (shapes per the PVE API: every body is {data}).
export const T = 1_800_000_000; // node clock, seconds
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
    "/api2/json/nodes/norco/storage/backups/content": d([
      { volid: "backups:backup/vzdump-qemu-109-a.vma.zst", vmid: 109, ctime: T - 86400 },
      { volid: "backups:backup/vzdump-qemu-109-b.vma.zst", vmid: 109, ctime: T - 3600 },
      { volid: "backups:backup/vzdump-qemu-100-a.vma.zst", vmid: 100, ctime: T - 7200 }
    ]),
    "/api2/json/nodes/main/storage/backups/content": d([{ volid: "backups:backup/vzdump-qemu-100-a.vma.zst", vmid: 100, ctime: T - 7200 }]),
    "/api2/json/nodes/norco/tasks": d([
      { type: "vzdump", id: "109", status: "OK", endtime: T - 3600 },
      { type: "vzdump", id: "109", status: "ERROR: timeout", endtime: T - 90000 }
    ]),
    "/api2/json/nodes/main/tasks": d([{ type: "vzdump", id: "", status: "job errors", endtime: T - 7000 }]),
    ...over
  };
}
