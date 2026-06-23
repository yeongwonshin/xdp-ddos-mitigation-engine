# Architecture

## 목표

XDP 기반 DDoS Mitigation Engine은 Linux NIC ingress 단계에서 SYN flood, UDP flood, ICMP flood를 빠르게 분류하고, source IP 단위 rate limiting과 정책 map을 기반으로 완화합니다.

## 구성 요소

### 1. XDP fast path: `ebpf/xdp_ddos_kern.c`

- Ethernet, optional VLAN, IPv4 header 파싱
- TCP SYN, UDP, ICMP 분류
- allowlist 우선 PASS
- blocklist 즉시 DROP 또는 audit
- reputation score 임계치 이상 DROP 또는 audit
- per-source/protocol/destination-port 1초 sliding-window rate limit
- stats map에 PASS/DROP 사유 기록

### 2. Control plane: `control/xdpctl.py`

- `bpftool`을 통해 pinned BPF map 업데이트
- 정책 config 적용
- allowlist/blocklist 추가·삭제·덤프
- reputation score 설정
- stats dump

### 3. Synthetic simulator: `sim/synthetic_simulator.py`

- 네트워크 패킷 생성 없음
- 공격 도구가 아닌 정책 검증용 합성 이벤트 생성기
- SYN/UDP/ICMP/mixed/normal 시나리오
- threshold tuning, audit-only 운영 검증

## 데이터 플로우

```text
NIC ingress
  ↓
XDP program
  ├─ allowlist_map     → PASS
  ├─ blocklist_map     → DROP/AUDIT
  ├─ reputation_map    → DROP/AUDIT
  ├─ rate_map          → threshold 초과 시 DROP/AUDIT
  └─ stats_map         → 관측/운영 통계
  ↓
Linux network stack 또는 DROP
```

## 정책 우선순위

1. malformed packet 방어
2. allowlist PASS
3. blocklist DROP/AUDIT
4. reputation DROP/AUDIT
5. protocol별 rate limit DROP/AUDIT
6. 기본 PASS

allowlist가 가장 높은 우선순위를 갖습니다. 운영 환경에서는 allowlist 범위를 최소화하고 변경 이력을 남기는 것을 권장합니다.

## 확장 아이디어

- IPv6 지원
- LPM trie 기반 CIDR allow/blocklist
- ring buffer event export
- Prometheus exporter
- 자동 reputation decay
- SYN cookie/proxy 연동
- TC egress/ingress fallback
- Kubernetes DaemonSet 배포
