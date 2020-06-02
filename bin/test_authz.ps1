$db_id = [guid]::NewGuid().ToString()
$env:AUTHZ_DB_FILE = 'test_data\\Authorization ' + $db_id
$server = Start-Process py -ArgumentList '-m', 'authz.test.server' -PassThru 

Write-Output $server.Id

#Start-Sleep -Seconds 2

py -m authz.test.tests $args

Stop-Process -Id $server.Id

