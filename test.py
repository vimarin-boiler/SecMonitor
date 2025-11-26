import winrm

session = winrm.Session('http://10.192.10.9:5985/wsman', auth=('monitor', 'monitor'), transport='ntlm')
result = session.run_cmd('ipconfig')
print(result.std_out.decode())