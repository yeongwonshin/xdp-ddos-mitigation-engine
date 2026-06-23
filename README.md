# XDP 기반 DDoS Mitigation Engine

> 목적: SYN/UDP/ICMP flood를 **탐지·완화**하기 위한 방어용 XDP/eBPF 프로젝트입니다.  
> 이 저장소의 시뮬레이터는 실제 네트워크 트래픽을 발생시키지 않고, 합성 이벤트로 정책 로직만 검증합니다.

## 핵심 기능

- XDP fast path에서 IPv4 TCP SYN, UDP, ICMP 트래픽 분류
- source IP 단위 rate limiting
- allowlist / blocklist control plane
- source IP reputation score 기반 차단
- per-CPU 통계 카운터
- 안전한 합성 트래픽 시뮬레이터
- `bpftool` 기반 운영 CLI 예시

## 디렉토리 구조

```text
xdp-ddos-mitigation-engine/
├── ebpf/                      # XDP/eBPF kernel fast path
│   └── xdp_ddos_kern.c
├── control/                   # 운영 제어 plane CLI
│   └── xdpctl.py
├── sim/                       # 방어 정책 합성 시뮬레이터, 네트워크 송신 없음
│   └── synthetic_simulator.py
├── config/
│   └── default_policy.json
├── docs/
│   ├── architecture.md
│   ├── safety.md
│   └── operations.md
├── scripts/
│   ├── build_ebpf.sh
│   ├── attach_xdp.sh
│   └── detach_xdp.sh
├── tests/
│   └── test_policy_sim.py
├── Makefile
└── LICENSE
```

## 요구사항

개발/실행 환경 예시:

- Linux kernel with eBPF/XDP support
- root 권한 또는 CAP_BPF/CAP_NET_ADMIN 권한
- clang/llvm
- bpftool
- iproute2
- libbpf headers (`libbpf-dev` 등)

Ubuntu 계열 예시:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm bpftool iproute2 libbpf-dev linux-headers-$(uname -r) make python3
```

## 빌드

```bash
make ebpf
```

## XDP 프로그램 부착/해제

운영망이 아닌 테스트 NIC, VM, lab namespace에서 먼저 검증하세요.

```bash
sudo make attach IFACE=eth0
sudo make detach IFACE=eth0
```

## Control plane 예시

기본 정책 적용:

```bash
sudo python3 control/xdpctl.py config apply --file config/default_policy.json
```

allowlist/blocklist:

```bash
sudo python3 control/xdpctl.py allow add 192.0.2.10
sudo python3 control/xdpctl.py block add 198.51.100.23
sudo python3 control/xdpctl.py block del 198.51.100.23
```

source IP reputation:

```bash
sudo python3 control/xdpctl.py reputation set 203.0.113.42 --score 80
```

통계 조회:

```bash
sudo python3 control/xdpctl.py stats
```

## 합성 시뮬레이터

네트워크 패킷을 생성하거나 전송하지 않습니다. 정책 로직 검증용 이벤트만 메모리에서 생성합니다.

```bash
python3 sim/synthetic_simulator.py --scenario syn --pps 10000 --duration 3 --src-count 100
python3 sim/synthetic_simulator.py --scenario mixed --pps 5000 --duration 5 --src-count 50 --json
```

테스트:

```bash
python3 -m unittest discover -s tests
```

## 안전 설계 원칙

- 공격 트래픽 발생 도구 미포함
- synthetic event 기반 simulator만 제공
- block action은 allowlist 우선순위보다 낮음: allowlist는 PASS
- 모든 완화는 reversible control plane으로 관리
- 운영 반영 전 dry-run, lab NIC, 낮은 임계치 검증 권장

## 라이선스

MIT License. 자세한 내용은 `LICENSE`를 참고하세요.
