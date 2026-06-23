IFACE ?= eth0

.PHONY: ebpf attach detach test sim clean tree

ebpf:
	./scripts/build_ebpf.sh

attach: ebpf
	./scripts/attach_xdp.sh $(IFACE)

detach:
	./scripts/detach_xdp.sh $(IFACE)

test:
	PYTHONPATH=. python3 -m unittest discover -s tests

sim:
	python3 sim/synthetic_simulator.py --scenario mixed --pps 5000 --duration 3 --src-count 100 --json

clean:
	rm -rf build/*.o build/vmlinux.h

tree:
	find . -maxdepth 3 -type f | sort
