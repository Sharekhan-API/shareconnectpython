from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as readme_file:
    readme = readme_file.read()

requirements = [
    "requests>=2.18.4",
    "six>=1.11.0",
    "cryptography>=3.0",        # AES-GCM for the request-token swap
    "websocket-client>=1.0",    # NOT the unrelated "websocket" package
]

setup(
    name='shareconnect',
    version='1.0.0.12',
    author='rg-sharekhanapi',
    author_email='shareconnect@sharekhan.com',
    description='Sharekhan Data Feed Trading Api Server',
    packages=find_packages(exclude=["test", "example"]),
    long_description=readme,
    long_description_content_type="text/markdown",
    install_requires=requirements,
    python_requires=">=3.7",
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Natural Language :: English",
        "Topic :: Office/Business :: Financial :: Investment",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Libraries"
    ],
)
