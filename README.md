# smtp25-guard

Блокирует TCP/UDP-порт 25 для хоста и Docker-контейнеров, устанавливает `iptables-persistent`, сохраняет правила после перезагрузки и удаляет временный установщик.

> Скрипт предназначен для Ubuntu/Debian со стандартным Docker iptables backend. На почтовом сервере не запускать.

## Запуск из GitHub

Замените `USERNAME` на имя вашего GitHub-аккаунта:

```bash
tmp="$(mktemp)" || exit 1; \
curl -fsSL https://raw.githubusercontent.com/USERNAME/smtp25-guard/main/smtp25-guard.sh -o "$tmp" && \
sudo bash "$tmp"; \
rc=$?; rm -f -- "$tmp"; exit "$rc"
```

На каждом этапе скрипт выводит `SUCCESS` или `FAILED`, а в конце — общий результат.

## Проверка

```bash
sudo iptables -vnL INPUT --line-numbers | grep 'dpt:25'
sudo iptables -vnL OUTPUT --line-numbers | grep 'dpt:25'
sudo iptables -vnL DOCKER-USER --line-numbers | grep 'dpt:25'
sudo systemctl is-enabled netfilter-persistent
```

Резервная копия исходных firewall-правил сохраняется в `/root/smtp25-guard-backup-*`.

`iptables-persistent` может удалить пакет UFW на системах, где они конфликтуют. Скрипт предварительно сохраняет активные правила, восстанавливает их после установки и затем сохраняет через `netfilter-persistent`.
