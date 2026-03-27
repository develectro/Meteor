from setuptools import setup, find_packages

setup(
    name="meteor",
    version="0.1.0",
    description="A modular CLI tool for port scanning, process mapping, log analysis, and Shodan integration.",
    author="Meteor Security",
    packages=find_packages(),
    install_requires=[
        "psutil>=5.9.0",
        "rich>=13.0.0",
        "shodan>=1.29.0"
    ],
    entry_points={
        "console_scripts": [
            "meteor=meteor.cli:main",
        ],
    },
    python_requires=">=3.10",
)
