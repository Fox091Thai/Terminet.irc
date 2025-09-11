Terminet.IRC
Terminet.IRC is a simple, lightweight just somehow worked. it's a my project that i want to make in past few year can be run on a single python file and everything is ready to used (if you correctly set your firewall for web hosting



Features:
- questionable security for log in: because since it's a little project so you no need to use your EMAIL or Phone number, so when you need to create your account it only requires username and password then after you registered the terminet will give you a unique code which is you need to keep it because there's no way to recovery your unique code
- Message logging for 512 messages and files keeping for 512 files before roll out: Because of terminet is just a simple IRC with basic functions so you no need to worry about your storage that much cuz i think 10 people with 10 server on DB might take space like under 25GB (include 512 uploaded files 50MB max) maybe? not quite sure, never tested before
- Message Logging: Encrypted message logs stored per-user, per-room: that is
- Old IRC style interface
- /img <link> /GIF <link> /Video <link> /help command
- Files uploading
- simple to use?
- no personal information needed
- run almost anywhere with python and internet access(server)
- run on web browsers (modern JavaScript support)

Who is compatible with this?
- small secret chat group
- the users that need privacy
- people who want to experiment with IRC

set up:
- set allow port [default at port 80] both inbound and outbound in firewall (if you use your computer as an IRC server)
- find your public IP
- or port forwarding 
- get python 3.9 and then pip install flask flask-socketio werkzeug cryptography
- Change keys in terminet_server.py (CUSTOM_ENCRYPTION_KEY = 'replace_with_your_secure_phrase') at line 48
- run the server (python3 terminet_server.py)
- Access it at:Login/Register → http://[your ip]/ (if you set it currectly)

Note:
- this thing only run on HTTP so if you have a time, i recommended you to make it HTTPS somehow.
- need to change your SECRET_KEY in line 29 for your encryption, the default key is "DefualtSecretKeyForTerminetV1.2"
- also change your Salt in line 76 for security, the default one is "default" 

about bug:
- Please expect the bug and mess up code.


Disclaimer 
- Please be aware that this projecr is mostly AI assisted. so security might be kinda questionable.
- please do not turn this into tech drama or eles 😭


building on hope and dream
- Terminet.IRC : If it works, It's a Miracle.
