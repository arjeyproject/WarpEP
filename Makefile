PYTHON ?= python3

.PHONY: help test selftest scan bundle lint clean install

help:
	@echo "make test      - run the full offline test suite"
	@echo "make selftest  - verify crypto vectors and the scan loop"
	@echo "make scan      - fast scan against Cloudflare WARP"
	@echo "make bundle    - build a single-file warpep.pyz"
	@echo "make install   - install into the current environment"

test:
	cd tests && $(PYTHON) -m unittest discover -s . -t .. -v

selftest:
	$(PYTHON) -m warpep selftest

scan:
	$(PYTHON) -m warpep scan --fast

bundle:
	$(PYTHON) scripts/build_bundle.py
	@echo "built warpep.pyz - run it with: python3 warpep.pyz scan"

install:
	$(PYTHON) -m pip install .

clean:
	rm -rf build dist *.egg-info warpep.pyz
	find . -name __pycache__ -type d -exec rm -rf {} +
