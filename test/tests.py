import requests
from requests.auth import HTTPBasicAuth
import http
import authz
import authz.db as db

endpoint = "http://localhost:5000"


def call_no_header():
    resp = requests.get(endpoint)
    assert resp.status_code == http.client.UNAUTHORIZED


def call_incorrect_authentication():
    headers = {"Authorization": "token: asdfsadfsadfadsfadsfdsafdsaf"}
    resp = requests.get(endpoint, headers=headers)
    assert resp.status_code == http.client.UNAUTHORIZED


user, _ = db.create_user("tester", False)


def call_correct_authentication():
    headers = {"Authorization": f"Token {user.api_key}"}
    resp = requests.get(endpoint, headers=headers)
    assert resp.status_code == http.client.OK


unauthorized_user, _ = db.create_user("unauthorized", False)


def call_with_unauthorized_user():
    headers = {"Authorization": f"Token {unauthorized_user.api_key}"}
    url = endpoint + "/protected"
    resp = requests.get(url, headers=headers)
    assert resp.status_code == http.client.UNAUTHORIZED

    cookies = {"api-key": unauthorized_user.api_key}
    resp = requests.get(url, cookies=cookies)
    assert resp.status_code == http.client.UNAUTHORIZED


admin, admin_password = db.create_user("admin", True)


def call_with_authorized_user():
    headers = {"Authorization": f"Token {admin.api_key}"}
    url = endpoint + "/protected"
    resp = requests.get(url, headers=headers)
    assert resp.status_code == http.client.OK

    cookies = {"api-key": admin.api_key}
    resp = requests.get(url, cookies=cookies)
    assert resp.status_code == http.client.OK


def call_with_invalid_username_in_path():
    headers = {"Authorization": f"Token {unauthorized_user.api_key}"}
    resp = requests.get(endpoint + "/admin/account", headers=headers)
    assert resp.status_code == http.client.UNAUTHORIZED

    headers = {"Authorization": f"Token {unauthorized_user.api_key}"}
    resp = requests.get(endpoint + "/admin/history", headers=headers)
    assert resp.status_code == http.client.UNAUTHORIZED


def call_with_valid_username_in_path():
    headers = {"Authorization": f"Token {admin.api_key}"}
    resp = requests.get(endpoint + "/admin/account", headers=headers)
    assert resp.status_code == http.client.OK

    headers = {"Authorization": f"Token {admin.api_key}"}
    resp = requests.get(endpoint + "/admin/history", headers=headers)
    assert resp.status_code == http.client.OK


def test_login():
    referrer = "/login"
    redirect = "/"
    url = endpoint + f"/login?referrer={referrer}&redirect={redirect}"

    # first test that we can't login with an API key in headers
    headers = {"Authorization": f"Token {admin.api_key}"}
    resp = requests.post(url, headers=headers, allow_redirects=False)
    assert resp.status_code == http.client.FOUND
    assert resp.headers.get("Location") == endpoint + referrer

    # test that we can login with basic HTTP auth
    resp = requests.post(
        url, auth=HTTPBasicAuth(admin.name, admin_password), allow_redirects=False
    )
    assert resp.status_code == http.client.FOUND
    assert resp.headers.get("Location") == endpoint + redirect


call_no_header()
call_incorrect_authentication()
call_correct_authentication()
call_with_unauthorized_user()
call_with_authorized_user()
call_with_invalid_username_in_path()
call_with_valid_username_in_path()
test_login()
