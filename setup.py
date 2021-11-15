from setuptools import setup, find_packages

setup(
    name="patcherex",
    version="1.2",
    description="The patcherex",
    packages=find_packages(),
    scripts=["patcherex/patcherex"],
    install_requires=[
        "angr",
        "capstone",
        "keystone-engine",
        "psutil",
        "timeout-decorator",
        "subprocess32",
        "compilerex",
        "fidget",
        "python-resources",
        "pyyaml",
        "pyelftools",
        "python-magic",
        "termcolor",
    ],
)
