from setuptools import setup, find_packages

setup(
    name="tetra",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "cloudflare",
        "tqdm",
        "pyyaml",
        "dnspython",
        "tencentcloud-sdk-python",
    ],
    entry_points={
        "console_scripts": [
            "tetra=tetra.tetra:main",
        ]
    },
    author="DictXiong",
    description="A DNS utility tool with multiple backends",
    python_requires=">=3.7",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
