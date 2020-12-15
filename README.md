# pull-docker-artifactory-layerwise
----------------

This utility pulls up the docker container images layer by layer  with the persistence, specially helpful in case of slow network when docker pull is slow  and it keeps pulling all the layers with every pull.
This utility will pull layers and in case the connection is broken, it will start from the place it left from the previous execution after all layers are pulled it will generate config and manifest files which can be directly loaded to the container runtime like docker daemon, podman etc.

after utility completes it will show command to load to docker daemon.

`
tar -cC <download location> . | docker load 
`




