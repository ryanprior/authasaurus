import requests
from requests.auth import HTTPBasicAuth
import http
from uuid import uuid4
from datetime import datetime, timedelta

from ..constants import POLICY_USE_UNTIL, POLICY_USE_ONCE_BEFORE
from .. import db
from ..db import create_api_key, get_user
import unittest

endpoint = "http://localhost:5000"


class AuthzTests(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        super(AuthzTests, self).setUpClass()
        self.user, _ = db.create_user("tester", False)
        self.unauthorized_user, _ = db.create_user("unauthorized", False)
        self.admin, self.admin_password = db.create_user("admin", True)

    def test_call_no_header(self):
        resp = requests.get(endpoint)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

    def test_call_incorrect_authentication(self):
        headers = {"Authorization": "token: asdfsadfsadfadsfadsfdsafdsaf"}
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

    def test_call_correct_authentication(self):
        api_key = create_api_key(self.user.user_id)
        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)

    def test_call_with_unauthorized_user(self):
        api_key = create_api_key(self.unauthorized_user.user_id)

        headers = {"Authorization": f"Token {api_key.key}"}
        url = endpoint + "/protected"
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

        cookies = {"api-key": api_key.key}
        resp = requests.get(url, cookies=cookies)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

    def test_call_with_authorized_user(self):
        api_key = create_api_key(self.admin.user_id)

        headers = {"Authorization": f"Token {api_key.key}"}
        url = endpoint + "/protected"
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)

        cookies = {"api-key": api_key.key}
        resp = requests.get(url, cookies=cookies)
        self.assertEqual(resp.status_code, http.client.OK)

    def test_call_with_invalid_username_in_path(self):
        api_key = create_api_key(self.unauthorized_user.user_id)

        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint + "/admin/account", headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

        # test a different arg (user instead of username)
        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint + "/admin/history", headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

    def test_call_with_valid_username_in_path(self):
        api_key = create_api_key(self.admin.user_id)

        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint + "/admin/account", headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)

        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint + "/admin/history", headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)

    def test_login(self):
        referrer = "/login"
        redirect = "/"
        url = endpoint + f"/login?referrer={referrer}&redirect={redirect}"
        login_user, login_user_password = db.create_user("login", True)

        # test that we can login with basic HTTP auth
        resp = requests.post(
            url,
            auth=HTTPBasicAuth(login_user.name, login_user_password),
            allow_redirects=False,
        )
        self.assertEqual(resp.status_code, http.client.FOUND)
        self.assertEqual(resp.headers.get("Location"), endpoint + redirect)
        self.assertEqual(get_user(resp.cookies.get("api-key")), login_user)

        # first test that we can't login with an API key in headers
        api_key = create_api_key(login_user.user_id)
        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.post(url, headers=headers, allow_redirects=False)
        self.assertEqual(resp.status_code, http.client.FOUND)
        self.assertEqual(resp.headers.get("Location"), endpoint + referrer)
        self.assertEqual(resp.cookies.get("api-key"), None)

    def test_rotate_api_key(self):
        api_key = create_api_key(self.admin.user_id)
        cookies = {"api-key": api_key.key}
        url = endpoint + "/logout"
        resp = requests.post(url, cookies=cookies, allow_redirects=False,)

        self.assertEqual(resp.status_code, http.client.FOUND)
        self.assertEqual(db.get_user(api_key=api_key.key), None)

    def test_lifecycle_use_until(self):
        api_key = create_api_key(
            self.admin.user_id,
            policy_id=2,
            policy_data=datetime.now() - timedelta(days=1),
        )
        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

    def test_lifecycle_use_once_before(self):
        api_key = create_api_key(
            self.admin.user_id,
            policy_id=3,
            policy_data=datetime.now() - timedelta(hours=1),
        )
        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

        api_key = create_api_key(
            self.admin.user_id,
            policy_id=3,
            policy_data=datetime.now() + timedelta(hours=1),
        )
        headers = {"Authorization": f"Token {api_key.key}"}
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)


if __name__ == "__main__":
    unittest.main()
