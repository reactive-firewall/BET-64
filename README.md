# About
This repo is basically my template for new repos/projects

# CI Template:

By default this template will assume that the Travis CI Service and Circle-CI Service are used for CI/CD

# Status

### master:
[![status](https://travis-ci.org/reactive-firewall/python-repo.svg?branch=master)](https://travis-ci.org/reactive-firewall/python-repo)
[![CircleCI](https://circleci.com/gh/reactive-firewall/python-repo/tree/master.svg?style=svg)](https://circleci.com/gh/reactive-firewall/python-repo/tree/master)
[![Appveyor](https://ci.appveyor.com/api/projects/status/6gggp1wpbnnjokm4/branch/master?svg=true)](https://ci.appveyor.com/project/reactive-firewall/python-repo/branch/master)
[![Python 3](https://pyup.io/repos/github/reactive-firewall/python-repo/python-3-shield.svg)](https://pyup.io/repos/github/reactive-firewall/PiAP-python-tools/)
[![Updates](https://pyup.io/repos/github/reactive-firewall/python-repo/shield.svg)](https://pyup.io/repos/github/reactive-firewall/python-repo/)
[![Test Coverage](https://api.codeclimate.com/v1/badges/f76f4e7e2eae6bff9b6a/test_coverage)](https://codeclimate.com/github/reactive-firewall/python-repo/test_coverage)
[![code coverage](https://codecov.io/gh/reactive-firewall/python-repo/branch/master/graph/badge.svg)](https://codecov.io/gh/reactive-firewall/python-repo/branch/master/)
[![Coverage Status](https://coveralls.io/repos/github/reactive-firewall/python-repo/badge.svg?branch=master)](https://coveralls.io/github/reactive-firewall/python-repo?branch=master)
[![coverity](https://scan.coverity.com/projects/13847/badge.svg)](https://scan.coverity.com/projects/reactive-firewall-python-repo)
[![Code Climate](https://codeclimate.com/github/reactive-firewall/python-repo/badges/gpa.svg)](https://codeclimate.com/github/reactive-firewall/python-repo)
[![CodeFactor](https://www.codefactor.io/repository/github/reactive-firewall/python-repo/badge)](https://www.codefactor.io/repository/github/reactive-firewall/python-repo)
[![codebeat badge](https://codebeat.co/badges/da1d8064-5736-49fd-9d61-d046aca38afb)](https://codebeat.co/projects/github-com-reactive-firewall-python-repo-master)
![Size](https://img.shields.io/github/languages/code-size/reactive-firewall/python-repo.svg)
![commits-since](https://img.shields.io/github/commits-since/reactive-firewall/python-repo/stable.svg?maxAge=9000)

### Stable:
[![status](https://travis-ci.org/reactive-firewall/python-repo.svg?branch=stable)](https://travis-ci.org/reactive-firewall/python-repo)
[![CircleCI](https://circleci.com/gh/reactive-firewall/python-repo/tree/stable.svg?style=svg)](https://circleci.com/gh/reactive-firewall/python-repo/tree/stable)
[![Appveyor](https://ci.appveyor.com/api/projects/status/6gggp1wpbnnjokm4/branch/stable?svg=true)](https://ci.appveyor.com/project/reactive-firewall/python-repo/branch/stable)
[![code coverage](https://codecov.io/gh/reactive-firewall/python-repo/branch/stable/graph/badge.svg)](https://codecov.io/gh/reactive-firewall/python-repo/branch/stable/)
[![code coverage](https://codecov.io/gh/reactive-firewall/python-repo/branch/stable/graph/badge.svg)](https://codecov.io/gh/reactive-firewall/python-repo/branch/stable/)
[![Coverage Status](https://coveralls.io/repos/github/reactive-firewall/python-repo/badge.svg?branch=stable)](https://coveralls.io/github/reactive-firewall/python-repo?branch=stable)
[![codebeat badge](https://codebeat.co/badges/87520e4a-6d24-4e98-a61e-6e9efc58f783)](https://codebeat.co/projects/github-com-reactive-firewall-python-repo-stable)

# How do I use this to create a new project repo?

(assuming new project is already forked on github to `MY-NEW-REPO`)

```bash
# cd /MY-AWSOME-DEV-PATH
git clone https://github.com/reactive-firewall/MY-NEW-REPO.git MY-NEW-REPO
# cd ./MY-NEW-REPO
```

# Dev Testing Template:

In a rush? Then use this:

```bash
make clean ; # cleans up from any previous tests hopefully
make test ; # runs the tests
make clean ; # cleans up for next test
```

Use PEP8 to check code style? Great! Try this:

```bash
make clean ; # cleans up from any previous tests hopefully
make test-style ; # runs the tests
make clean ; # cleans up for next test
```

Want more tests? Cool! Try `tox`:

```bash
make clean ; # cleans up from any previous tests hopefully
make test-tox ; # runs the tox tests
make clean ; # cleans up for next test
```

# Next steps:

Like automation? Then integrate away, this template can take it!
(hint: @travis-ci, @houndci-bot, @pyup-bot, @stickler-ci, @circleci, @codecov-io, @lemurheavy, @coverallsapp, @codeclimate)

Not in a rush? Then be sure to edit the badges in the README.
(hint: `sed -e 's/python-repo/MY-NEW-REPO' ./README.md`)


[![License - MIT](https://img.shields.io/github/license/reactive-firewall/python-repo.svg?maxAge=2592000)](https://github.com/reactive-firewall/python-repo/blob/stable/LICENSE.md)

