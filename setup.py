from setuptools import setup, find_packages

setup(
    name="z3rgrush",
    version="1.0.0",
    author="derErntehelfer",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "z3rgrush = z3rgrush.z3rgRush:main",  # Installs /usr/bin/z3rgrush
            "z3rg = z3rgrush.z3rgRush:main",
        ]
    },
    install_requires=["stem", "requests"],  # Add to requirements.txt too
    python_requires=">=3.8",
    description="Tor-powered web fuzzer",
)
