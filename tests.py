import requests
import settings
import http
import db

def call_no_header():
    resp = requests.get(settings.endpoint)
    assert(resp.status_code == http.client.UNAUTHORIZED)

def call_incorrect_authentication():
    headers = {'Authorization': 'token: asdfsadfsadfadsfadsfdsafdsaf'}
    resp = requests.get(settings.endpoint, headers = headers)
    assert(resp.status_code == http.client.UNAUTHORIZED)

user, _ = db.create_user("tester", False)

def call_correct_authentication():
    headers = {'Authorization': f'Token {user.api_key}'}
    resp = requests.get(settings.endpoint, headers = headers)
    assert(resp.status_code == http.client.OK)

unauthorized_user, _ = db.create_user("unauthorized", False)

def call_with_unauthorized_user():
    headers = {'Authorization': f'Token {unauthorized_user.api_key}'}
    resp = requests.get(settings.endpoint +"/protected", headers = headers)
    assert(resp.status_code == http.client.UNAUTHORIZED)

admin, _ = db.create_user("admin", False)

def call_with_authorized_user():
    headers = {'Authorization': f'Token {admin.api_key}'}
    resp = requests.get(settings.endpoint+"/protected", headers = headers)
    assert(resp.status_code == http.client.OK)

def call_with_invalid_username_in_path():
    headers = {'Authorization': f'Token {unauthorized_user.api_key}'}
    resp = requests.get(settings.endpoint+"/admin/account", headers = headers)
    assert(resp.status_code == http.client.UNAUTHORIZED)

    headers = {'Authorization': f'Token {unauthorized_user.api_key}'}
    resp = requests.get(settings.endpoint+"/admin/history", headers = headers)
    assert(resp.status_code == http.client.UNAUTHORIZED)

def call_with_valid_username_in_path():
    headers = {'Authorization': f'Token {admin.api_key}'}
    resp = requests.get(settings.endpoint+"/admin/account", headers = headers)
    assert(resp.status_code == http.client.OK)

    headers = {'Authorization': f'Token {admin.api_key}'}
    resp = requests.get(settings.endpoint+"/admin/history", headers = headers)
    assert(resp.status_code == http.client.OK)



call_no_header()
call_incorrect_authentication()
call_correct_authentication()
call_with_unauthorized_user()
call_with_authorized_user()
call_with_invalid_username_in_path()
call_with_valid_username_in_path()