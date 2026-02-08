from setuptools import setup, find_packages

setup(
    name='remoteRF_host',
    version='0.1',
    packages=find_packages(where='src'),
    package_dir={"":'src'},
    install_requires=[
        "grpcio", "protobuf", "numpy", "prompt_toolkit", "python-dotenv", "dotenv"
    ],
    entry_points={
        'console_scripts': [
            'hostrf=remoteRF_host.hostrf_cli:main',
        ],
    },
)