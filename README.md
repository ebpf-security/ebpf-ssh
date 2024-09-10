# eBPF-SSH
eBPF-SSH is an open source ssh-audit tool built using eBPF, we makes BPF programs easier to build.
[![Build Status](https://drone.grafana.net/api/badges/grafana/beyla/status.svg?ref=refs/heads/main)](https://ebpf-security.github.io/navihtml/ebpf-dump.html)

## Requirements
Security monitoring purposes, It runs on/requires Linux Kernel >= 5.10 such as the following platforms:
* Ubuntu 22.04+
* Fedora 33+
* RHEL 9.0+
* Debian 12+
* Rocky Linux 9.0+
* OpenSUSE 15+
* ...

## Building & Running
```console
# Ubuntu
sudo apt-get install -y make gcc libelf-dev

# RHEL
sudo yum install -y make gcc elfutils-libelf-devel

$ make
  cc  -w -o ebpf-ssh  sshcmdline.c   ./libbpf/libbpf.a -lelf -lz -lm  -I./libbpf/ 

$ ./ebpf-ssh 
  TIME     COMM             PID     CMD
  10:36:53 bash             1453    ls -al
  10:36:56 bash             1453    history
```
Loading eBPF program  requires root privileges 


## eBPF-ssh+
**eBPF-ssh+** is a paid version and completely open source too, main features are:
- Web interfaces
- Record ssh successful login and failed logs
- Full history of ssh history command
- SSH client threats discovered
- Pure-C eBPF implementation

**Free Trial**

```console
$ wget https://ebpf-security.github.io/ebpf-ssh
$ chmod +x ./ebpf-ssh 
$ ./ebpf-ssh 
  1. Kill all of  processes...........................
  2. Init  ok.........................................
  3. System is running................................
```

After loading is complete, Open a browser to http://<host>:9998/ to access the Web UI.
Full Trial version available at [https://ebpf-security.github.io/navihtml/ebpf-ssh.html](https://ebpf-security.github.io/navihtml/ebpf-ssh.html)

How to stop?

```console
$ ./ebpf-dump stop
```

<a href="https://github.com/ebpf-security/ebpf-security.github.io/blob/main/img/1.png"><img height="500" width="820" src="https://github.com/ebpf-security/ebpf-security.github.io/blob/main/img/1.png"></img></a>
&nbsp;


## Contact Us
* Mail to `ebpf-sec@hotmail.com`
Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

## License
This project is licensed under the terms of the
[MIT license](/LICENSE).
