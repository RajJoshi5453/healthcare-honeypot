#!/usr/bin/env python3
"""
generate_fs.py

Purpose: Generate a Cowrie-compatible fs.pickle fake filesystem that simulates
a medical IoT device. Cowrie's filesystem loader expects a dictionary of paths
where each value is an object with st_mode, st_nlink, st_uid, st_gid, st_size,
st_mtime, st_atime, st_ctime, st_ino attributes.

For directories: st_mode must have the directory bit (0o040000), and the object
must have a .name attribute containing a list of filenames inside that directory.
For files: st_mode must have the regular file bit (0o100000), and the object must
have a .file attribute containing a list of bytes chunks (file contents).

We use types.SimpleNamespace because it is a standard-library class that is
perfectly picklable and unpicklable by any Python interpreter. Cowrie accesses
all attributes via dot notation, so SimpleNamespace instances work seamlessly.

Usage:
    cd honeypot/cowrie
    python3 generate_fs.py

Output:
    fs.pickle  (binary file consumed by Cowrie's configuration)
"""

import pickle
import os
from types import SimpleNamespace
from pathlib import Path

# Fake filesystem content: a dictionary of absolute paths -> file/dir objects.
FS = {}


def make_dir(path, entries, uid=0, gid=0, mode=0o40755):
    """Create a SimpleNamespace that looks like a directory to Cowrie."""
    return SimpleNamespace(
        st_mode=0o040000 | (mode & 0o7777),  # directory + permissions
        st_nlink=2 + len(entries),
        st_uid=uid,
        st_gid=gid,
        st_size=4096,
        st_mtime=1700000000,
        st_atime=1700000000,
        st_ctime=1700000000,
        st_ino=abs(hash(path)) % (2**31),
        name=entries,
    )


def make_file(path, content, uid=0, gid=0, mode=0o100644):
    """Create a SimpleNamespace that looks like a regular file to Cowrie."""
    data = content.encode("utf-8")
    return SimpleNamespace(
        st_mode=0o100000 | (mode & 0o7777),  # regular file + permissions
        st_nlink=1,
        st_uid=uid,
        st_gid=gid,
        st_size=len(data),
        st_mtime=1700000000,
        st_atime=1700000000,
        st_ctime=1700000000,
        st_ino=abs(hash(path)) % (2**31),
        file=[data],
    )


# --- Root filesystem layout ---
# Minimal Linux root structure to convince attackers this is a real embedded device.
FS["/"] = make_dir("/", ["bin", "etc", "opt", "tmp", "var", "dev", "proc", "usr", "home", "root"])
FS["/bin"] = make_dir("/bin", ["sh", "busybox", "ls", "cat", "echo", "chmod", "wget", "curl", "python"])
FS["/bin/sh"] = make_file("/bin/sh", "#!/bin/sh\necho BusyBox v1.29.3 built-in shell (ash)")
FS["/bin/busybox"] = make_file("/bin/busybox", "ELF binary placeholder")
FS["/bin/ls"] = make_file("/bin/ls", "ELF binary placeholder")
FS["/bin/cat"] = make_file("/bin/cat", "ELF binary placeholder")
FS["/bin/echo"] = make_file("/bin/echo", "ELF binary placeholder")
FS["/bin/chmod"] = make_file("/bin/chmod", "ELF binary placeholder")
FS["/bin/wget"] = make_file("/bin/wget", "ELF binary placeholder")
FS["/bin/curl"] = make_file("/bin/curl", "ELF binary placeholder")
FS["/bin/python"] = make_file("/bin/python", "ELF binary placeholder")

FS["/etc"] = make_dir("/etc", ["hostname", "passwd", "dicom", "init.d", "shadow", "network"])
FS["/etc/hostname"] = make_file("/etc/hostname", "MedDevice-HVAC-01")
FS["/etc/passwd"] = make_file(
    "/etc/passwd",
    "root:x:0:0:root:/root:/bin/sh\n"
    "hvac-service:x:1001:1001:HVAC Service:/home/hvac:/bin/sh\n"
    "meduser:x:1003:1003:Medical User:/home/meduser:/bin/sh\n"
)
FS["/etc/shadow"] = make_file("/etc/shadow", "root:*:18500:0:99999:7:::\n")

# --- Medical device specific paths ---
# These directories and files are the "bait" that convinces attackers they found
# a hospital IoT device rather than a generic honeypot.
FS["/opt"] = make_dir("/opt", ["medical"])
FS["/opt/medical"] = make_dir("/opt/medical", ["bin", "config", "logs", "firmware"])
FS["/opt/medical/bin"] = make_dir("/opt/medical/bin", ["heartbeat", "telemetry", "dicom-bridge", "update.sh"])
FS["/opt/medical/bin/heartbeat"] = make_file(
    "/opt/medical/bin/heartbeat",
    "#!/bin/sh\n# Heartbeat monitor for MedDevice-HVAC-01\nwhile true; do\n  curl -s http://192.168.100.1/status > /dev/null\n  sleep 30\ndone\n"
)
FS["/opt/medical/bin/telemetry"] = make_file(
    "/opt/medical/bin/telemetry",
    "#!/bin/sh\n# Send temperature and humidity to PACS gateway\npython /opt/medical/bin/dicom-bridge --mode=telemetry\n"
)
FS["/opt/medical/bin/dicom-bridge"] = make_file(
    "/opt/medical/bin/dicom-bridge",
    "#!/usr/bin/env python3\nimport sys, socket\n# DICOM bridge for HL7 integration (stub)\nprint('DICOM bridge starting...')\n"
)
FS["/opt/medical/bin/update.sh"] = make_file(
    "/opt/medical/bin/update.sh",
    "#!/bin/sh\n# Firmware update script\nURL=${1:-http://firmware.medvendor.local/latest.bin}\nwget -O /tmp/firmware.bin $URL\n"
)
FS["/opt/medical/config"] = make_dir("/opt/medical/config", ["device.cfg", "network.json"])
FS["/opt/medical/config/device.cfg"] = make_file(
    "/opt/medical/config/device.cfg",
    "DEVICE_ID=HVAC-01-9472\nFLOOR=3\nWARD=ICU-North\nPACS_GATEWAY=192.168.100.15\nDICOM_PORT=104\n"
)
FS["/opt/medical/config/network.json"] = make_file(
    "/opt/medical/config/network.json",
    '{"vlan":100,"gateway":"192.168.100.1","dns":["192.168.100.5"]}\n'
)
FS["/opt/medical/logs"] = make_dir("/opt/medical/logs", ["device.log", "errors.log"])
FS["/opt/medical/logs/device.log"] = make_file(
    "/opt/medical/logs/device.log",
    "2024-01-15 09:23:00 HVAC-01 temperature=22.4 humidity=45%\n"
    "2024-01-15 09:24:00 HVAC-01 temperature=22.5 humidity=46%\n"
    "2024-01-15 09:25:00 HVAC-01 temperature=22.6 humidity=45%\n"
)
FS["/opt/medical/logs/errors.log"] = make_file(
    "/opt/medical/logs/errors.log",
    "2024-01-15 08:00:00 WARN: DICOM heartbeat timeout to 192.168.100.15:104\n"
)
FS["/opt/medical/firmware"] = make_dir("/opt/medical/firmware", ["manifest.txt", "backup"])
FS["/opt/medical/firmware/manifest.txt"] = make_file(
    "/opt/medical/firmware/manifest.txt",
    "VERSION=2.1.4\nDATE=2023-11-20\nVENDOR=MedTech Embedded\n"
)

# --- DICOM configuration directory ---
FS["/etc/dicom"] = make_dir("/etc/dicom", ["scripts", "peers.cfg"])
FS["/etc/dicom/scripts"] = make_dir("/etc/dicom/scripts", ["storescp.sh", "query.sh"])
FS["/etc/dicom/scripts/storescp.sh"] = make_file(
    "/etc/dicom/scripts/storescp.sh",
    "#!/bin/sh\n# DICOM Storage SCP listener\nstorescp -v -aet MEDDEVICE01 -od /var/dicom/incoming 104\n"
)
FS["/etc/dicom/scripts/query.sh"] = make_file(
    "/etc/dicom/scripts/query.sh",
    "#!/bin/sh\n# DICOM Query/Retrieve (C-FIND) helper\necho 'Querying PACS for patient studies...'\n"
)
FS["/etc/dicom/peers.cfg"] = make_file(
    "/etc/dicom/peers.cfg",
    "PACS-PRIMARY=192.168.100.15:104\nPACS-BACKUP=192.168.100.16:104\nRIS-GATEWAY=192.168.100.20:2575\n"
)

# --- Standard Linux directories to complete the illusion ---
FS["/tmp"] = make_dir("/tmp", [])
FS["/var"] = make_dir("/var", ["log", "dicom"])
FS["/var/log"] = make_dir("/var/log", ["syslog"])
FS["/var/log/syslog"] = make_file("/var/log/syslog", "Jan 15 09:00:01 MedDevice-HVAC-01 cron[45]: (root) CMD (/opt/medical/bin/heartbeat)\n")
FS["/var/dicom"] = make_dir("/var/dicom", ["incoming"])
FS["/var/dicom/incoming"] = make_dir("/var/dicom/incoming", [])
FS["/dev"] = make_dir("/dev", ["null", "zero", "random", "urandom", "tty"])
FS["/dev/null"] = make_file("/dev/null", "")
FS["/dev/zero"] = make_file("/dev/zero", "")
FS["/dev/random"] = make_file("/dev/random", "")
FS["/dev/urandom"] = make_file("/dev/urandom", "")
FS["/dev/tty"] = make_file("/dev/tty", "")
FS["/proc"] = make_dir("/proc", ["version", "cpuinfo", "meminfo"])
FS["/proc/version"] = make_file("/proc/version", "Linux version 4.14.98-v7+ (root@meddevice) (gcc version 7.3.0) #1 SMP armv7l\n")
FS["/proc/cpuinfo"] = make_file("/proc/cpuinfo", "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nCPU architecture: 7\n\n")
FS["/proc/meminfo"] = make_file("/proc/meminfo", "MemTotal:         512000 kB\nMemFree:           42000 kB\n")
FS["/usr"] = make_dir("/usr", ["bin"])
FS["/usr/bin"] = make_dir("/usr/bin", ["python3"])
FS["/usr/bin/python3"] = make_file("/usr/bin/python3", "ELF binary placeholder")
FS["/home"] = make_dir("/home", ["hvac", "meduser"])
FS["/home/hvac"] = make_dir("/home/hvac", [])
FS["/home/meduser"] = make_dir("/home/meduser", [])
FS["/root"] = make_dir("/root", [".bash_history", "notes.txt"])
FS["/root/.bash_history"] = make_file(
    "/root/.bash_history",
    "cd /opt/medical/bin\n./heartbeat &\nls /etc/dicom/\ncat /etc/dicom/peers.cfg\n"
)
FS["/root/notes.txt"] = make_file(
    "/root/notes.txt",
    "TODO: rotate DICOM credentials before FDA audit\nTemp password: default123\n"
)
FS["/etc/init.d"] = make_dir("/etc/init.d", ["medical-device"])
FS["/etc/init.d/medical-device"] = make_file(
    "/etc/init.d/medical-device",
    "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: medical-device\n# Default-Start: 2 3 4 5\n### END INIT INFO\n/opt/medical/bin/heartbeat\n"
)
FS["/etc/network"] = make_dir("/etc/network", ["interfaces"])
FS["/etc/network/interfaces"] = make_file(
    "/etc/network/interfaces",
    "auto eth0\niface eth0 inet static\n    address 192.168.100.50\n    netmask 255.255.255.0\n    gateway 192.168.100.1\n"
)


def main():
    output_path = Path(__file__).parent / "fs.pickle"
    print(f"[INFO] Generating fake medical IoT filesystem: {output_path.resolve()}")

    with open(output_path, "wb") as f:
        pickle.dump(FS, f, protocol=pickle.HIGHEST_PROTOCOL)

    print(f"[INFO] fs.pickle written successfully ({len(FS)} paths).")
    print("[INFO] Run 'docker compose up' to mount this into the Cowrie container.")


if __name__ == "__main__":
    main()
