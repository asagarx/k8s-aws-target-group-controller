from setuptools import setup, find_packages

setup(
    name="aws-targetgroup-controller",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "kopf",
        "kubernetes",
        "boto3",
    ],
    python_requires=">=3.9",
)