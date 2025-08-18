Terminet.IRC
Terminet.IRC is a simple, lightweight just somehow worked. it's a my project that i want to make in past few year can be run on a single python file and everything is ready to used (if you correctly set your firewall for web hosting
Features:
- questionable security for log in: because since it's a little project so you no need to use your EMAIL or Phone number, so when you need to create your account it only requires username and password then after you registered the terminet will give you a unique code which is you need to keep it because there's no way to recovery your unique code
- Message logging for 512 messages before roll out: Because of terminet is just a simple IRC that lightweight so you no need to worry about your storage run out cuz i think 10 people with 10 server on DB might take space like 5MB maybe? not quite sure, never tested before
- Message Logging: Encrypted message logs stored per-user, per-room: that is
- Old ICR style interface
- /img <link> /GIF <link> /Video <link> /help command
- simple to use?
- no personal information needed
set up:
- set allow port [default at port 5000] both inbound and outbound in firewall (if you use your computer as an IRC server)
- find your public IP
- get python 3.9 and then pip install flask flask-socketio werkzeug cryptography
- Change keys in terminet_server.py (app.config['SECRET_KEY'] = 'your_secret_key_here'
CUSTOM_ENCRYPTION_KEY = 'replace_with_your_secure_phrase')
- run the server (python3 terminet_server.py)
- Access it at:Login/Register → http://[your ip]:5000/ (if you set it currectly)
file structure
terminet_server.py    # Main server file
logs/                # Encrypted message logs (auto-created)
terminet.db          # SQLite database (auto-created)
templates/
├── index.html        # Login/Register page
└── IRC.html         # Chat interface

