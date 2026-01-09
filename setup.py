import pathlib, re
from setuptools import setup

for line in open('cvproxy.py'):
  if line.startswith('__version__'):
    exec(line)
    break

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()
README = re.sub(r'^.*?#', '#', README, flags=re.DOTALL)

setup(
  name="cvproxy",
  version=__version__,
  python_requires=">=3.10",
  description="CVProxy - CloudVision Proxy",
  long_description=README,
  long_description_content_type="text/markdown",
  url="https://github.com/cmason3/cvproxy",
  author="Chris Mason",
  author_email="chris@netnix.org",
  license="MIT",
  classifiers=[
    "Development Status :: 4 - Beta",
    "Programming Language :: Python :: 3"
  ],
  packages=["cvproxy"],
  install_requires=["pyavd>=5.7.2", "jsonschema"],
  entry_points={
    "console_scripts": [
      "cvproxy=cvproxy:main",
    ]
  }
)
