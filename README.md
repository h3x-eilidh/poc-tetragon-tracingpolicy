## Tetragon for Security observability using Tracing Policies

<img src="https://tetragon.io/svgs/tetragon-shield.svg" alt="Tetragon" width="200"/>

<!-- ![Tetragon](https://tetragon.io/svgs/tetragon-shield.svg) -->



In this proof-of-concept, our focus is on showcasing how Tetragon can help us in detecting anomalies (a privilege escalation attempt, in this case) within a Kubernetes cluster using a tracing policy.  
The simulation involves a controlled scenario where a process attempts to manipulate setuid bits, illustrating the significance of early detection in preventing potential security breaches.

### Create the cluster with Kind

Use Kind to create a multi-node Kubernetes cluster with one control plane node and three worker nodes.

```
cat <<EOF > kind-multinode.conf && kind create cluster --name k8s --config kind-multinode.conf
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
# networking:
#  disableDefaultCNI: true
EOF
```

### Add Cilium/Tetragon Helm Repo and Install Helm Chart

Add the Cilium Helm repository, update the repository index, and install the *Tetragon* Helm chart in the `kube-system` namespace.

```
helm repo add cilium https://helm.cilium.io && helm repo update && helm install tetragon cilium/tetragon -n kube-system
```

### Apply Tetragon Policy

Apply a Tetragon policy that monitors and logs attempts to use the setuid system call to set setuid bits to 0.

``` 
kubectl apply -f https://raw.githubusercontent.com/cilium/tetragon/main/examples/policylibrary/privileges/privileges-setuid-root.yaml
```

The policy syntax is straightforward, it defines a Kprobe configuration for tracing the `__sys_setuid` system call and send an alert when the conditions are met.

```
spec:
  kprobes:
  - call: "__sys_setuid"
    syscall: false
    return: true
    args:
    - index: 0
      type: "int"
    returnArg:
      index: 0
      type: "int"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Equal"
        values:
        - "0"
      matchActions:
      - action: Post
        rateLimit: "1m"  # Rate limit messages to 1min
```

### Create Pod with Anomalous Behavior

Define a Kubernetes pod manifest with an init container that compiles a C program (`setuid-root.c`) attempting to set its setuid bits to 0. The main container runs this C program in a loop, simulating a process trying to escalate privileges.

```
apiVersion: v1
kind: Pod
metadata:
  name: setuid-root-pod
spec:
  initContainers:
  - name: init-gcc
    image: ubuntu:latest
    command: ["/bin/bash", "-c"]
    volumeMounts:
    - name: source
      mountPath: /src
    args:
      - |
        apt-get update && apt-get install -y gcc
        cat <<EOF > /src/setuid-root.c
        #define _GNU_SOURCE
        #include <stdio.h>
        #include <stdlib.h>
        #include <unistd.h>
        #include <sys/wait.h>
        int main() {
            if (setuid(0) == 0) {
                printf("Privilege escalation successful. This process now has root privileges (UID: %d)\n", getuid());
                } else {
                perror("Privilege escalation failed");
                }
            return 0;
        }
        EOF
        gcc /src/setuid-root.c -o /src/setuid-root
  containers:
  - name: run-container
    image: ubuntu:latest
    command: ["/bin/bash"]
    args: ["-c", "while true; do /src/setuid-root; sleep 5; done"]
    securityContext:
      runAsUser: 1000
      runAsGroup: 1000
    volumeMounts:
    - name: source
      mountPath: /src
  volumes:
  - name: source
    emptyDir: {}
```

We can inspect the logs of the running pod to observe the behavior of the C program, which repeatedly attempts to set its setuid bits to 0.

```
k logs setuid-root-pod -c run-container
```

Now we can use Tetragon to detect and log events related to the anomalous setuid behavior. The Tetragon DaemonSet (`ds/tetragon`) is deployed in the `kube-system` namespace, and we use the `tetra getevents -o compact` command to retrieve and display these events in a human-readable way.

```
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```

The events indicate that there is a process attempting to use the system call `__sys_setuid` to set its setuid bits to 0, providing insight into potential security threats and privilege escalation attempts in the Kubernetes cluster.

![Tetragon Logs](https://i.ibb.co/3B2kq88/g4w-Bd-Kupp-Screenshot-2024-01-18-at-15-41-15.png)

Executing `tetra getevents` provides a comprehensive JSON representation of the entire event stack. 

```
{"process_exec":{"process":{"exec_id":"*=","pid":293470,"uid":1000,"cwd":"/","binary":"/usr/bin/sleep","arguments":"5","flags":"execve rootcwd clone","start_time":"2024-01-18T15:37:19.566563222Z","auid":4294967295,"pod":{"namespace":"default","name":"setuid-root-pod","container":{"id":"containerd://*","name":"run-container","image":{"id":"docker.io/library/ubuntu@sha256:*","name":"docker.io/library/ubuntu:latest"},"start_time":"*","pid":1483},"workload":"setuid-root-pod","workload_kind":"Pod"},"docker":"*","parent_exec_id":"*=","tid":293470},"parent":{"exec_id":"*=","pid":247248,"uid":1000,"cwd":"/","binary":"/bin/bash","arguments":"-c \"while true; do /src/setuid-root; 
```

This resource includes further details, including the workload responsible for generating anomalies.  

```[...]"pod":{"namespace":"default","name":"setuid-root-pod","container":{"id":"containerd://*","name":"run-container","image":[...]```

Now we are well-equipped to effectively take proactive measures against any potential security threats.

https://tetragon.io/docs/concepts/tracing-policy/selectors/#actions-filter

