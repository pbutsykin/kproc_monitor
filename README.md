# Intrusion detection system (IDS) Test platform

Content:

* kproc_monitor - Intrusion detection monitor based on kprobes. Linux kernel module.
                  (Can't be used in production, only for research and testing. KProbe based solution has limits, races, etc).
* functional - drop/restore privileges test.
* CVE   - examples of real CVEs detected by IDS.
* vuln  - kernel module with artificial vulnerabilities for testing IDS.
* tests - python tests for IDS based on real CVEs and artificially created with kernel module from vulns/.

## What types of intrusions are detected?

- unauthorized zeroing uid/gid/euid/suid in cred struct (in order to privilege escalation attacks).
- unauthorized disabling SELinux.
- unauthorized modification mmap_min_addr value.
- unauthorized modification security bits SMEP/SMAP/UMIP in CR4 reg.

## What happens when intrusion is detected?

In case of unauthorized disabling Linux kernel security mechanisms, it will be
turned back on, and the event will be stored to event log (/proc/kcs/log).

In case of detection of illegal process with escalated privilege the process
will be killed and syscall in the context of which this intrusion was detected
will return -EPERM, and of course the event will stored to the event log.
However, this behavior can be destructive for the system and while IDS isn't tested
well enough 'sysctl -w kcs.enforcing=0' option will be available to disable proactive
protection.

```
sysctl options:
kcs.enforcing     - enable/disbale procces monitor protection (enabled by default).
kcs.separated_gid - IDS doesn't track unauthorized modification of cred.gid value (as it's done for uid),
                    but with enabled kcs.separated_gid mode IDS can detect situation when uid != 0 and gid == 0,
                    and take appropriate measures with such process. However, though this state of process is very
                    unusual and suspicious, but from the point of view Linux this combination of rights is correct.
                    Therefore, this mode exists as option (enabled by default).
kcs.cpu_recovery  - restoring CPU security features (disabled by default). An access violation imposed by
                    SMEP/SMAP/UMIP leads to kernel crash. It's probably not the best outcome, especially if
                    the intrusion can be caught more gently by IDS.
```

## Integration with higher level security monitor

/proc/kcs/info - General information about IDS configuration, example:
 # cat /proc/kcs/info
 ```
 kc security:
 root process monitor: enabled
 selinux protection: enabled
 mmap_min_addr protection: enabled
 cpu security:[ smep] protection enabled
 ```

/proc/kcs/log - Event log, example:
 # cat /proc/kcs/log
```
 KCS event log (caught 5 events, limit is 100 messages):
 [273043282077] selinux_verify: 'enabled' value restored: auto-test.py(pid:18374 uid:0) --> insmod(pid:18618, uid:0)
 [273043282677] selinux_verify: 'enforcing' value restored: auto-test.py(pid:18374 uid:0) --> insmod(pid:18618, uid:0)
 [273043283281] mmap_min_addr_verify: 'dac_mmap_min_addr' value restored: auto-test.py(pid:18374 uid:0) --> insmod(pid:18618, uid:0)
 [273043292698] rprocess_verify: Privilege escalation detected!: bash(pid:18623 uid:1001) --> vpwn(pid:18624, uid:0)
 [273043303026] rprocess_verify: Privilege escalation detected!: bash(pid:18627 uid:1001) --> vpwn_fork(pid:18628, uid:0)
```

## Why not use kprobes?

In general kprobes was designed for tracing, so it has limitations. (https://lwn.net/Articles/132196/)

1. It is prohibited to take mutex in kprobe handler
2. kretprobes can overflow and miss your hook calls

However, it's quite convinient for testing the basic ideas, IDS algorithms and strategies.

