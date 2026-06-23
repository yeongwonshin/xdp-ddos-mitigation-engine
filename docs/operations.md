# Operations Guide

## 빌드

```bash
make ebpf
```

`build/vmlinux.h`가 없으면 Makefile이 `/sys/kernel/btf/vmlinux`에서 생성합니다.

## 부착

```bash
sudo make attach IFACE=eth0
```

기본 attach는 generic XDP 모드입니다. 드라이버 native XDP가 필요하면 `scripts/attach_xdp.sh`를 조정하세요.

## 해제

```bash
sudo make detach IFACE=eth0
```

## 정책 적용

```bash
sudo python3 control/xdpctl.py config apply --file config/default_policy.json
```

기본 정책은 `audit_only=true`입니다. DROP을 실제 적용하려면 설정 파일에서 `audit_only=false`로 변경한 후 적용합니다.

## allowlist / blocklist

```bash
sudo python3 control/xdpctl.py allow add 192.0.2.10
sudo python3 control/xdpctl.py block add 198.51.100.23
sudo python3 control/xdpctl.py block del 198.51.100.23
```

## Reputation

```bash
sudo python3 control/xdpctl.py reputation set 203.0.113.42 --score 90
```

`reputation_drop_score` 이상의 score는 DROP/AUDIT 대상입니다.

## Observability

```bash
sudo python3 control/xdpctl.py stats
sudo bpftool map dump pinned /sys/fs/bpf/xdp_ddos/stats_map
```

per-CPU map은 CPU별 counter가 표시되므로 운영 exporter에서는 합산해야 합니다.

## Rollback

```bash
sudo make detach IFACE=eth0
```

또는 audit-only 정책을 재적용합니다.

```bash
jq '.audit_only=true' config/default_policy.json > /tmp/audit-policy.json
sudo python3 control/xdpctl.py config apply --file /tmp/audit-policy.json
```
