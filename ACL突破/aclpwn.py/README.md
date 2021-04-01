# aclpwn.py

![Python 2.7 and 3 compatible](https://img.shields.io/badge/python-2.7%2C%203.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/aclpwn.svg)
![License: MIT](https://img.shields.io/pypi/l/aclpwn.svg)

Aclpwn.py is a tool that interacts with [BloodHound](https://github.com/BloodHoundAD/BloodHound) to identify and exploit ACL based privilege escalation paths. It takes a starting and ending point and will use Neo4j pathfinding algorithms to find the most efficient ACL based privilege escalation path. Aclpwn.py is similar to the PowerShell based [Invoke-Aclpwn](https://github.com/fox-it/Invoke-ACLPwn), which you can read about in [our blog](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/).

## Dependencies and installation
Aclpwn.py is compatible with both Python 2.7 and 3.5+. It requires the `neo4j-driver`, `impacket` and `ldap3` libraries. You can install aclpwn.py via pip: `pip install aclpwn`. For Python 3, you will need the `python36` [branch of impacket](https://github.com/SecureAuthCorp/impacket/tree/python36) since the master branch (and versions published on PyPI) are Python 2 only at this point. 

## Usage
For usage and documentation, see the [wiki](https://github.com/fox-it/aclpwn.py/wiki/), for example the [quickstart page](https://github.com/fox-it/aclpwn.py/wiki/Quickstart).

## Features
aclpwn.py currently has the following features:
- Direct integration with BloodHound and the Neo4j graph database (fast pathfinding)
- Supports any reversible ACL based attack chain (no support for resetting user passwords right now)
- Advanced pathfinding (Dijkstra) to find the most efficient paths
- Support for exploitation with NTLM hashes (pass-the-hash)
- Saves restore state, easy rollback of changes
- Can be run via a SOCKS tunnel
- Written in Python (2.7 and 3.5+), so OS independent

## Mitigations and detection
aclpwn.py does not exploit any vulnerabilities, but relies on misconfigured (often because of delegated privileges) or insecure default ACLs. To solve these issues, it is important to identify potentially dangerous ACLs in your Active Directory environment with BloodHound. For detection, Windows Event Logs can be used. The relevant event IDs are described in [our blog](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
