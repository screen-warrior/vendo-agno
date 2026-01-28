"""
NetCertify - Enterprise Firewall Certification Framework

Setup script for package installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text() if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                # Remove version specifiers for setup.py
                requirements.append(line.split("#")[0].strip())

setup(
    name="netcertify",
    version="1.0.0",
    author="NetCertify Team",
    author_email="netcertify@example.com",
    description="Enterprise-grade firewall certification automation framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/netcertify",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pydantic>=2.5.0",
        "PyYAML>=6.0.1",
        "Jinja2>=3.1.2",
        "rich>=13.7.0",
        "click>=8.1.7",
    ],
    extras_require={
        "pyats": [
            "pyats>=24.0",
            "genie>=24.0",
        ],
        "paloalto": [
            "pan-os-python>=1.11.0",
        ],
        "fortinet": [
            "fortigate-api>=1.0.0",
        ],
        "all": [
            "pyats>=24.0",
            "genie>=24.0",
            "pan-os-python>=1.11.0",
            "fortigate-api>=1.0.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "mypy>=1.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netcertify=netcertify.cli:main",
        ],
    },
    include_package_data=True,
)
