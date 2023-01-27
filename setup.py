import os

from setuptools import find_packages, setup

short_description = 'A Django app to utilise full capabilities of reCaptcha enterprise.'

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

install_requirements = [
    "django>=1.0",
]

setup(
    name='django-recaptcha-enterprise',
    version='0.0.9',
    packages=find_packages(),
    install_requires=install_requirements,
    include_package_data=True,
    license='MIT License',
    description=short_description,
    long_description=short_description,
    long_description_content_type="text/markdown",
    url='https://github.com/rapidbounce/django-recaptcha-enterprise',
    author='Panagiotis Skarlas',
    author_email='devs@rapidbounce.co',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 1.9',
        'Framework :: Django :: 1.10',
        'Framework :: Django :: 1.11',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 3.0',
        'Framework :: Django :: 3.1',
        'Framework :: Django :: 3.2',
        'Framework :: Django :: 4.0',
        'Framework :: Django :: 4.1',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
    ],
)
