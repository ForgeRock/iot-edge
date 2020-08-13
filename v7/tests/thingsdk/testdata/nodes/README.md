## Tree node data

Anvil will use the data contained in the this folder to create AM Auth Tree nodes.

Given the example directory structure:

    dependednt  -> typeA -> node1
    independent -> typeB -> node2
                       -> node3
                -> typeC -> node4

Anvil will load `node1` of `typeA`, `node2` and `node3` of `typeB`
and `node4` of `typeC`.
Independent nodes are loaded before dependent nodes (for example, `node1` would be loaded last)

When a tree node is created:

    * the type is taken from directory name
    * the name is taken from the json file name
    * the configuration is taken from the contents of the JSON file.
    This is equivalent to the data sent with the REST request to create a tree node.

To convert a test node from a sample curl\REST request (e.g. as observed in the admin UI):

        curl -s -X PUT \
            -H "Content-Type: application/json" \
            -H "Accept-API-Version: resource=1.0, protocol=2.0" \
            -H "iPlanetDirectoryPro: ${token}" \
            -d '{"_id":"27e6dc74-3385-4145-9d71-dfc33976f3d6"}' \
            ${base_url}/nodes/UsernameCollectorNode/27e6dc74-3385-4145-9d71-dfc33976f3d6

create the json file:

    mkdir -p independent/UsernameCollectorNode
    echo '{"_id":"27e6dc74-3385-4145-9d71-dfc33976f3d6"}` \
        > ./independent/UsernameCollectorNode/27e6dc74-3385-4145-9d71-dfc33976f3d6.json
