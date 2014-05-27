# Copyright 2014 DreamHost, LLC
#
# Author: DreamHost, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from setuptools import setup, find_packages


setup(
    name='akanda-router',
    version='0.2.0',
    description='A packet filter based router appliance',
    author='DreamHost',
    author_email='dev-community@dreamhost.com',
    url='http://github.com/dreamhost/akanda',
    license='BSD',
    install_requires=[
        'flask>=0.9',
        'gunicorn>=0.14.6',
        'netaddr>=0.7.7',
        'eventlet>=0.9.17',
        'requests>=0.14.1,<=1.2.0',
    ],
    namespace_packages=['akanda'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'akanda-configure-ssh ='
            'akanda.router.commands.management:configure_ssh',
            'akanda-configure-gunicorn = '
            'akanda.router.commands.management:configure_gunicorn',
            'akanda-configure-default-pf = '
            'akanda.router.commands.management:configure_default_pf',
            'akanda-api-dev-server = akanda.router.api.server:main',
            'akanda-metadata-proxy = akanda.router.metadata_proxy:main',
        ]
    },
)
