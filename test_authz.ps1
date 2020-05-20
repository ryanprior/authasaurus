$db_id = [guid]::NewGuid().ToString()
$env:AUTHZ_DB_FILE = 'DB_Authorizaion ' + $db_id
$server = Start-Process py -ArgumentList '-m', 'authz.test.server'
py -m authz.test.tests $args
Stop-Process $server