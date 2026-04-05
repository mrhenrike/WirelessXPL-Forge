from setuptools import setup, find_packages


with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="wirelessxpl",
    version="1.0.0b0",
    description="WirelessXPL-Forge: 802.11 / WPA / WPA3 / BLE lab shell and PCAP tooling",
    long_description=long_description,
    author="Threat9",
    author_email="marcin@threat9.com",
    url="https://github.com/mrhenrike/WirelessXPL-Forge",
    download_url="https://github.com/mrhenrike/WirelessXPL-Forge",
    packages=find_packages(),
    include_package_data=True,
    scripts=('wxf.py',),
    entry_points={},
    python_requires='>=3.8',
    install_requires=[
        "requests>=2.32.4",
        "paramiko",
        "pysnmp",
        "pycryptodome",
        "setuptools",
        "telnetlib3; python_version >= '3.13'",
    ],
    extras_require={
        "tests": [
            "pytest",
            "pytest-forked",
            "pytest-xdist",
            "flake8",
        ],
        # Optional: heavyweight; enables CUDA logits in AutoPwn ml_use_gpu when PyTorch sees CUDA.
        "ml-gpu": [
            "torch>=2.0.0",
        ],
        "ml-lite": [
            "numpy>=1.24",
            "scikit-learn>=1.3",
        ],
    },
    classifiers=[
        "Operating System :: POSIX",
        "Environment :: Console",
        "Environment :: Console :: Curses",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
)
