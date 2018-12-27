"""
Flask-UWNetID
-------------

Provides one-line SAML authentication for the UW NetID IDP.
Uses flask_login behind the scenes.

Routes should be protected with `@login_required`.

"""
from setuptools import setup


setup(
    name='Flask-UWNetID',
    version='1.0',
    author='Nik Krumm',
    author_email='nkrumm@uw.edu',
    description='Provides SAML-based auth for the UW NetID IDP.',
    long_description=__doc__,
    py_modules=['flask_uwnetid'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'flask_login',
        'python3-saml'
    ]
)