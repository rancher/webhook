# Build Instructions

The base tag this release is branched from is `v0.2.6`

###Create Environment Variables

```
export DOCKER_REPO=<Docker Repository>
export DOCKER_NAMESPACE=<Docker Namespace>
export DOCKER_TAG=v0.2.6-BFS
```

###Build and Push Images


By default, Rancher uses the latest tag on the Git branch as the image tag, so create the tag and run make:
```
git tag ${DOCKER_TAG}
make
```

Alternatively you can skip creating the tag and simply pass an environment variable to make:

```
TAG=${DOCKER_TAG} make
```
Once the build completes successfully, tag and push the images:

```
docker tag rancher/rancher-webhook:v0.2.6 ${DOCKER_REPO}/${DOCKER_NAMESPACE}/rancher:${DOCKER_TAG}
docker push ${DOCKER_REPO}/${DOCKER_NAMESPACE}/rancher-webhook:${DOCKER_TAG}
```
