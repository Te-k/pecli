PWD = $(shell pwd)

check:
	flake8 .
	ruff check .

clean:
	rm -rf $(PWD)/build $(PWD)/dist $(PWD)/pecli.egg-info

dist:
	python3 setup.py sdist bdist_wheel

upload:
	python3 -m twine upload dist/*
