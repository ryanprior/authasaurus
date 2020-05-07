# Add authorization to your web app

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

### Start the test server

```sh-session
$ python3 -m authz.test.server
```

### Run the tests

```sh-session
$ python3 -m authz.test.tests
```
