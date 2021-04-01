import re
from builtins import input
def getnodemap(nodes):
    mymap = {}
    for node in nodes:
        mymap[node.id] = node
    return mymap

def print_path(record):
    nmap = getnodemap(record['p'].nodes)
    # Iterate the path
    pathtext = '(%s)-' % record['p'].nodes[0].get('name')
    for el in record['p']:
        pathtext += '[%s]->(%s)-' % (el.type, nmap[el.end].get('name'))
    pathtext = pathtext[:-1]
    return pathtext

def build_path(record):
    path = []
    nmap = getnodemap(record['p'].nodes)
    # Iterate the path
    for el in record['p']:
        path.append((el, nmap[el.end]))
    return path

def build_rest_path(nodes, rels):
    path = []
    nmap = getnodemap(nodes)
    # Iterate the path
    pathtext = '(%s)-' % nodes[0].get('name')
    for i, el in enumerate(nodes[1:]):
        path.append((rels[i], el))
    return path

def print_rest_path(nodes, rels):
    nmap = getnodemap(nodes)
    # Iterate the path
    pathtext = '(%s)-' % nodes[0].get('name')
    for i, el in enumerate(nodes[1:]):
        pathtext += '[%s]->(%s)-' % (rels[i].type, el.get('name'))
    pathtext = pathtext[:-1]
    return pathtext

def get_modify_length(record):
    return len([el for el in record['p'] if el.get('isacl', False)])

def append_domain(name, otype, domain):
    """
    Append the domain to a name, depending on its type. If the name already is in domain
    specification, return it as-is
    """
    if otype == 'Domain':
        if name == '':
            return domain.upper()
    elif otype == 'Computer':
        if not '.' in name:
            # Computers use a dot as separator
            return '%s.%s' % (name, domain)
    elif otype == 'User':
        if not '@' in name:
            # Users use an @ as separator
            return '%s@%s' % (name, domain)
    elif otype == 'Group':
        if not '@' in name:
            # Groups use an @ as separator
            return '%s@%s' % (name, domain)
    # Default: return name as-is
    return name

# Ask the user to choose a path
def prompt_path(pathlen):
    chosen = False
    path = None
    while not chosen:
        try:
            pathstr = input('Please choose a path [0-%d] ' % (pathlen-1))
            path = int(pathstr)
        except ValueError:
            print('Invalid path specified!')
        except KeyboardInterrupt:
            print()
            return False
        if path is None:
            continue
        if path >= 0 and path < pathlen:
            chosen = True
        else:
            print('Invalid path specified!')
    return path

def domain2ldap(domain):
    return 'DC=' + ',DC='.join(str(domain).rstrip('.').split('.'))

def ldap2domain(ldap):
    return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]

# Get SAM name from bloodhound name (user/group/computer)
def get_sam_name(fullname):
    if not '@' in fullname and '.' in fullname:
        # Computer account.  Format: computer.domain.local
        # also append the $ sign used for computer accounts
        return fullname.split('.', 1)[0]+'$'
    else:
        # User or group
        return fullname.rsplit('@', 1)[0]

# Get domain from bloodhound name (user/group/computer)
def get_domain(fullname):
    if not '@' in fullname and '.' in fullname:
        # Computer account. Format: computer.domain.local
        return fullname.split('.', 1)[1]
    else:
        # Group or user. Format: group@domain.local
        return fullname.rsplit('@', 1)[1]
