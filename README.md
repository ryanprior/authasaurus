# Add authorization to your web app

Authors of network microservices should always follow strong security practices.
Often they struggle to do so without sacrificing velocity or being forced to
adopt a heavy framework. Authasaurus adds solid security with minimal added
complexity.

## Example

### Flask

TODO

Check out [authz/test/server.py](authz/test/server.py) which demonstrates a
simple web app.

## Testing

### Dependencies

- Python 3.7
- requests
- flask
- bcrypt

#### Using pip

```sh-session
$ pip install -r requirements.txt
```

Note: before installing with pip, make sure you have bcrypt's dependencies. (see
https://pypi.org/project/bcrypt/)

#### Using Guix

```sh-session
$ guix environment -m requirements.scm
```

### Start a dev server

```sh-session
$ python3 -m authz.test.server
```

Then connect on `localhost:5000`.

### Run the tests

The tests are in the `authz.test.tests` module, but you don't want to run that
module directly because it requires certain environment variables to be set for
both the test server & pytest module.

The `test-authz` script sets these environment variables, collects logs, and
prints test output to your terminal. It's the most convenient way to run the
tests:

```sh-session
$ bin/test-authz
```

We made an attempt at a similar PowerShell script but didn't get far. Take a
look at `bin/test_authz.ps1` for more info, and please if you're a PowerShell
expert help us improve this script!
