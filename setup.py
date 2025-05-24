# setup.py
from setuptools import setup, find_packages

setup(
    name="SecCQL",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "click", "InquirerPy", "rich", "cmd2", "cloudscraper"
    ],
    entry_points={
        "console_scripts": [
            "SecCQL=cli.console:main",  # Ensure this points to the correct main function
        ],
    },
)