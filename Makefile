clean:
	rm -f -r build/
	rm -f -r dist/
	rm -f -r *.egg-info

publish: clean
	python3 setup.py sdist bdist_wheel
	python3 -m twine upload dist/*

rebuild: build clean

build:
	pip install .