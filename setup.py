from distutils.core import setup

setup(
    name='surl',
    version='0.1',
    author='Celso Providelo',
    author_email='celso.providelo@canonical.com',
    scripts=['surl.py'],
    url='http://pypi.python.org/pypi/surl/',
    license='LICENSE',
    description='Ubuntu Store API thin wrapper.',
    install_requires=[
        "requests",
        "pymacaroons",
    ],
)
