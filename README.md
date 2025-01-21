# <p align="center">ft_strace</p>

> Ce projet consiste à recoder une partie de la commande strace.
>
> Strace is a debugging tool under Linux to monitor system calls use by a program,
> and all the signals it receives, similar to the tool truss on other Unix systems.
> It was made possible through a feature of the Linux kernel called ptrace.

## Install

```bash
apt update -y
apt install -y make
apt install -y gcc
```

```bash
git clone https://github.com/Skalyaeve/ft_strace.git
cd ft_strace && make

./ft_strace -h
```
