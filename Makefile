clean:
	rm -f -r build/
	rm -f -r *.egg-info

publish: clean
	python3 setup.py sdist bdist_wheel
	python3 -m twine upload dist/*

rebuild: clean
	python3 setup.py install

build:
	python3 setup.py install