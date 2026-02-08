from setuptools import setup, find_packages

setup(
    name='remoteRF_server',
    version='0.1',
    packages=find_packages(where='src'),
    package_dir={"":'src'},
    install_requires=[
        "grpcio", "protobuf", "numpy", "prompt_toolkit", "python-dotenv", "grpcio-tools"
    ],
    entry_points={
        'console_scripts': [
            'RRRFserver = remoteRF_server.server.grpc_server:main',
        ],
    },
)