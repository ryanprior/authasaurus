max_api_key_length = 128  # in Unicode characters

# length in bytes; length of username + password + redirect url
max_auth_form_length = 1024

# If this is false, cookies are sent as httponly, in which case browsers will
# not allow the page to get the API key from the cookie. If you need to do
# that, set this to True instead.
# Warning: this could make it easier to leak API keys.
allow_javascript_to_read_api_key = False
