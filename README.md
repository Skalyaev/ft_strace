# <p align="center">ft_strace</p>

> Ce projet consiste à recoder une partie de la commande strace.
>
> Strace est un outil de débogage sous Linux
> permettant de surveiller les appels système utilisés par un programme
> ainsi que tous les signaux qu'il reçoit,
> similaire à l'outil truss sur d'autres systèmes Unix.
> Cet outil est rendu possible grâce à une fonctionnalité du noyau Linux appelée ptrace.

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
