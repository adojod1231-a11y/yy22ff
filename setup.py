from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="yy22ff",
    version="1.0.0",
    author="yy22ff",
    author_email="adojod1231@gmail.com",
    description="Full-auto web vulnerability scanner: crawling, fingerprinting, SQLi, XSS, LFI, RFI, SSRF, CMDi, SSTI, file-upload exploitation, TLS analysis.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://t.me/yy22ff",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Natural Language :: Arabic",
        "Intended Audience :: Developers",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
        "colorama>=0.4.4",
    ],
    entry_points={
        "console_scripts": [
            "yy22ff=yy22ff:cli",
        ],
    },
)
