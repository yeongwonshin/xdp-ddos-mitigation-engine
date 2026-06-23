# Safety Notes

이 프로젝트는 방어·탐지·완화 시스템입니다.

## 포함하지 않는 것

- 실제 DDoS 발생기
- raw socket 기반 패킷 송신기
- 외부 대상 트래픽 생성 스크립트
- 서비스 장애 유발 목적의 자동화

## 포함하는 것

- Linux XDP 방어 프로그램
- 운영자가 명시적으로 관리하는 allowlist/blocklist/reputation map
- synthetic-only simulator
- audit-only 기본 정책

## 운영 안전 절차

1. 처음에는 `audit_only=true`로 실행합니다.
2. lab NIC 또는 VM에서 stats map과 정상 트래픽 영향도를 확인합니다.
3. allowlist를 먼저 구성합니다.
4. 작은 임계치 변경을 단계적으로 적용합니다.
5. DROP 모드 전환 전 rollback 명령을 준비합니다.
6. 장애 발생 시 즉시 `sudo make detach IFACE=<iface>`로 XDP 프로그램을 제거합니다.

## Simulator 안전성

`sim/synthetic_simulator.py`는 in-memory event만 생성합니다. 소켓을 열지 않고, 패킷을 송신하지 않으며, PCAP replay 기능도 제공하지 않습니다.
