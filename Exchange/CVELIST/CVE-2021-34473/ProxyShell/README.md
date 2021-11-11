# ProxyShell

## Install
```
git clone https://github.com/ktecv2000/ProxyShell
cd ProxyShell
virtualenv -p $(which python3) venv
source venv/bin/activate
pip3 install pypsrp
cp wsman.py venv/lib/*/site-packages/pypsrp/wsman.py
```

## Usage
```
python3 exploit.py <target-exchange-server-ip> <email>
```
