# Network Security Probe

## Requirements

The project was developed on Linux ubuntu-bionic, kernel version 4.15.0.
The script `env_setup.sh` will setup a vagrant VM with the required dependencies for you (requires virtualbox & vagrant).

## Getting started

1) Start a minikube cluster

```
sudo minikube start --vm-driver=none
```

2) Vendor go dependencies

```
go mod vendor
```

3) Build NSP

```
make build
```

4) (optional) Build the ping/pong/attacker containers

```
make demo
```

5) Fetch and export Datadog API key

```
export DD_API_KEY=****
```

6) Start the Datadog Agent

```
make run_agent
```

7) Start NSP

```
make run
```

8) (optional) Start the ping-pong demo

```
sudo helm install ping-pong static/charts/ping-pong
```

9) (optional) After modifying the profiles in `static/charts/ping-pong/templates`, you can update them with

```
sudo helm upgrade ping-pong static/charts/ping-pong
```
The changes will automatically be picked up by NSP and the new profiles should be applied within seconds.

### Code-generator Setup

Manually clone `https://github.com/kubernetes/code-generator` (branch `v0.17.0`) in `/vendor/code-generator`.
