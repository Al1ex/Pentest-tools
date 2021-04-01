from aclpwn import utils, database

# Cost map for relationships
costmap = {
    'MemberOf': 0,
    'AddMember': 1,
    'GenericAll': 1,
    'GenericWrite': 1,
    'WriteOwner': 3,
    'WriteDacl': 2,
    'DCSync': 0,
    'Owns': 2,
    'GetChangesAll': 0,
    'GetChanges': 0,
    'AllExtendedRights': 2
}



def dijkstra_find(fromid, toid, dbhost):
    # This is "documented" here
    # https://github.com/neo4j/neo4j/blob/3.3/community/server/src/main/java/org/neo4j/server/rest/web/DatabaseActions.java
    # https://github.com/neo4j/neo4j/blob/3.3/community/server/src/main/java/org/neo4j/server/domain/RelationshipExpanderBuilder.java
    rellist = [{"type": rel, "direction": "out"} for rel in costmap.keys()]
    data = {
      "to" : "http://%s:7474/db/data/node/%s" % (dbhost, toid),
      "max_depth" : 100,
      "relationships" : rellist,
      "algorithm" : "dijkstra",
      "cost_property": "aclpwncost",
      "default_cost": 1
    }
    resp = database.restapi.post('http://%s:7474/db/data/node/%s/paths' % (dbhost, fromid), json=data)
    data = resp.json()
    paths = []
    for path in data:
        nodes, rels = resolve_rest_path(path)
        paths.append((nodes, rels, path))
    return paths

def dijkstra_find_cypher(startnode, endnode, starttype='User', endtype='User'):
    query = "MATCH (n:%s {name: {startnode}}), (m:%s {name: {endnode}}) " \
            "CALL algo.shortestPath.stream(n, m, 'aclpwncost', " \
            "{nodeQuery:null, relationshipQuery:null, defaultValue:200.0, direction:'OUTGOING'}) " \
            "YIELD nodeId, cost " \
            "RETURN nodeId as node, cost"

    with database.driver.session() as session:
        with session.begin_transaction() as tx:
            print(query % (starttype, endtype))
            path = tx.run(query % (starttype, endtype),
                          startnode=startnode,
                          endnode=endnode,
                          property='aclpwncost')
    paths = []
    nodes, rels = resolve_dijkstra_path(path)
    paths.append((nodes, rels, path))
    return paths


queries = {
    # Query all shortest paths
    'shortestonly': "MATCH (n:%s {name: {startnode}}),"
                    "(m:%s {name: {endnode}}),"
                    " p=allShortestPaths((n)-[:MemberOf|AddMember|GenericAll|"
                    "GenericWrite|WriteOwner|WriteDacl|Owns|DCSync|GetChangesAll|AllExtendedRights*1..]->(m))"
                    " RETURN p",
    # Query all simple paths (more expensive query than above)
    # credits to https://stackoverflow.com/a/40062243
    'allsimple':    "MATCH (n:%s {name: {startnode}}),"
                    "(m:%s {name: {endnode}}),"
                    " p=(n)-[:MemberOf|AddMember|GenericAll|"
                    "GenericWrite|WriteOwner|WriteDacl|Owns|DCSync|GetChangesAll|AllExtendedRights*1..]->(m)"
                    "WHERE ALL(x IN NODES(p) WHERE SINGLE(y IN NODES(p) WHERE y = x))"
                    " RETURN p"
}


def get_path(startnode, endnode, starttype='User', endtype='User', querytype='allsimple'):
    with database.driver.session() as session:
        with session.begin_transaction() as tx:
            return tx.run(queries[querytype] % (starttype, endtype),
                          startnode=startnode,
                          endnode=endnode)

def get_path_cost(record):
    nmap = utils.getnodemap(record['p'].nodes)
    cost = 0
    for el in record['p']:
        cost += costmap[el.type]
    return cost

def resolve_dijkstra_path(path):
    nodes = []
    rels = []
    nq = "MATCH (n)-[w {aclpwncost: {cost}}]->(m) WHERE ID(n) = {source} AND ID(m) = {dest} RETURN n,w,m"
    bnq = "MATCH (n)-[w]->(m) WHERE ID(n) = {source} AND ID(m) = {dest} RETURN n,w,m"
    with database.driver.session() as session:
        with session.begin_transaction() as tx:
            pv = path.values()
            for i in range(1, len(pv)):
                res = tx.run(nq, source=pv[i-1][0], cost=pv[i][1]-pv[i-1][1], dest=pv[i][0])
                data = res.single()
                # No result, most likely an invalid path, but query for a relationship with any cost regardless
                if not data:
                    res = tx.run(bnq, source=pv[i-1][0], dest=pv[i][0])
                    data = res.single()
                nodes.append(data['n'])
                rels.append(data['w'])
            # Append the last node
            nodes.append(data['m'])
    return (nodes, rels)

def resolve_rest_path(path):
    nodes = []
    rels = []
    nq = "MATCH (n) WHERE id(n) = {id} RETURN n"
    rq = "MATCH ()-[n]-() WHERE id(n) = {id} RETURN n LIMIT 1"
    with database.driver.session() as session:
        with session.begin_transaction() as tx:
            for nodeurl in path['nodes']:
                nid = nodeurl.split('/')[-1]
                res = tx.run(nq, id=int(nid))
                nodes.append(res.single()['n'])
            for relurl in path['relationships']:
                nid = relurl.split('/')[-1]
                res = tx.run(rq, id=int(nid))
                rels.append(res.single()['n'])
    return (nodes, rels)
