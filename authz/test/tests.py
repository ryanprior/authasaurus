import requests
from requests.auth import HTTPBasicAuth
import http

from .. import db
import unittest

endpoint = "http://localhost:5000"

class AuthzTests(unittest.TestCase):

    def setUp(self):
        self.user, _ = db.create_user("tester", False)
        self.unauthorized_user, _ = db.create_user("unauthorized", False)
        self.admin, self.admin_password = db.create_user("admin", True)

    def test_call_no_header(self):
        resp = requests.get(endpoint)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

    def test_call_incorrect_authentication(self):
        headers = {"Authorization": "token: asdfsadfsadfadsfadsfdsafdsaf"}
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code,  http.client.UNAUTHORIZED)

    def test_call_correct_authentication(self):
        headers = {"Authorization": f"Token {self.user.api_key}"}
        resp = requests.get(endpoint, headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)

    def test_call_with_unauthorized_user(self):
        headers = {"Authorization": f"Token {self.unauthorized_user.api_key}"}
        url = endpoint + "/protected"
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

        cookies = {"api-key": self.unauthorized_user.api_key}
        resp = requests.get(url, cookies=cookies)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

    def test_call_with_authorized_user(self):
        headers = {"Authorization": f"Token {self.admin.api_key}"}
        url = endpoint + "/protected"
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)

        cookies = {"api-key": self.admin.api_key}
        resp = requests.get(url, cookies=cookies)
        self.assertEqual(resp.status_code, http.client.OK)


    def test_call_with_invalid_username_in_path(self):
        headers = {"Authorization": f"Token {self.unauthorized_user.api_key}"}
        resp = requests.get(endpoint + "/admin/account", headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)

        headers = {"Authorization": f"Token {self.unauthorized_user.api_key}"}
        resp = requests.get(endpoint + "/admin/history", headers=headers)
        self.assertEqual(resp.status_code, http.client.UNAUTHORIZED)


    def test_call_with_valid_username_in_path(self):
        headers = {"Authorization": f"Token {self.admin.api_key}"}
        resp = requests.get(endpoint + "/admin/account", headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)

        headers = {"Authorization": f"Token {self.admin.api_key}"}
        resp = requests.get(endpoint + "/admin/history", headers=headers)
        self.assertEqual(resp.status_code, http.client.OK)


    def test_login(self):
        referrer = "/login"
        redirect = "/"
        url = endpoint + f"/login?referrer={referrer}&redirect={redirect}"

        #first test that we can't login with an API key in headers
        headers = {"Authorization": f"Token {self.admin.api_key}"}
        resp = requests.post(url, headers=headers, allow_redirects=False)
        self.assertEqual(resp.status_code, http.client.FOUND)
        self.assertEqual(resp.headers.get("Location"), endpoint + referrer)

        #test that we can login with basic HTTP auth
        resp = requests.post(
            url, auth=HTTPBasicAuth(self.admin.name, self.admin_password), allow_redirects=False
        )
        self.assertEqual(resp.status_code, http.client.FOUND)
        self.assertEqual(resp.headers.get("Location"), endpoint + redirect)


if __name__ == "__main__":
    unittest.main()
