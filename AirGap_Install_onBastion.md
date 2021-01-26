[toc]

# OpenShift 4.5.20离线安装笔记

## 安装环境

- Client Center VMware vSphere，Beijing Folder Liujie


- 堡垒机( Bastion) ：可以联外网，作为DNS服务器, Web服务器, NFS服务器, LB服务器, 注册服务器等
- BootStrap, Master, Worker只能访问内网 

```json
bastion  172.20.51.113
boot     172.20.51.114 00:50:56:b5:29:5f
master0  172.20.51.115 00:50:56:b5:d9:ab
master1  172.20.51.116 00:50:56:b5:83:7b
master2  172.20.51.117 00:50:56:b5:e5:9d
worker0  172.20.51.118 00:50:56:b5:eb:7b
worker1  172.20.51.119 00:50:56:b5:d5:7d
Netmask: 255.255.255.224

# Install-config及DNSmasq文件配置应当照此填写
BaseDomain : example.com
Cluster name : lab
```

### DNS配置(修改hosts文件)

```bash
$ vim /etc/hosts
```
添加如下内容
```json

127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

172.20.51.113   Bastion
172.20.15.113   api
172.20.15.113   api-int

# 后续步骤的节点命名要保持一致
172.20.51.114   bootstrap
172.20.51.115   master-0 
172.20.51.116   master-1
172.20.51.117   master-2
172.20.15.115   etcd-0     # etcd与master一致
172.20.15.115   etcd-1
172.20.15.117   etcd-2
172.20.51.118   worker-0
172.20.51.119   worker-1

```
### 配置环境变量
直接修改 或者 写入`~/.bash_profile`文件中(写入后重启有效)
```bash
export REGISTRY_SERVER="Bastion"
export REGISTRY_PORT=5000
export LOCAL_REGISTRY="${REGISTRY_SERVER}:${REGISTRY_PORT}"
export REGISTRY_USER="admin"
export REGISTRY_PASSWORD="admin"
export OCP_RELEASE="4.5.20"
export RHCOS_RELEASE="4.5.6"
export PRODUCT_REPO="openshift-release-dev"
export RELEASE_NAME="ocp-release"
export EMAIL="Cheng.Gang.Zhu@ibm.com"
export LOCAL_REPOSITORY="ocp4/openshift4"
export LOCAL_SECRET_JSON="/ocp/ocp_pullsecret.json"
export REMOTE_SECRET_JSON='/ocp/pull-secret.txt'
export COMBINED_SECRET_JSON='/ocp/pull-secret-2.txt'
```


##  堡垒机准备工作
### 安装依赖
```bash
yum install -y bind-utils net-tools epel-release
yum -y install wget podman httpd-tools jq --nogpgcheck
```
### 开启转发

```bash
$ cat <<EOF > /etc/sysctl.d/99-custom.conf 
net.ipv4.ip_forward = 1 
EOF

$ sysctl -p /etc/sysctl.d/99-custom.conf
```
###  Selinux 配置

```bash
$ vi /etc/selinux/config # 改成 Permissive 或者 disabled
```
### 关闭防火墙等

```bash
$ systemctl stop iptables
$ systemctl stop ip6tables
$ systemctl stop firewalld
$ systemctl disable iptables
$ systemctl disable ip6tables
$ systemctl disable firewall
```
### 安装配置Dnsmasq
```bash
$ yum install –y dnsmasq
$ vim /etc/dnsmasq.conf 
```
修改如下：
```yaml
port=53
domain-needed 
bogus-priv 
resolv-file=/etc/resolv.dnsmasq 
no-poll 
address=/apps.lab.example.com/172.20.51.113
expand-hosts 
domain=lab.example.com
# 按照按照环境部分内容填写
dhcp-range=172.20.51.114,172.20.51.119,255.255.255.224,12h
dhcp-host=00:50:56:b5:29:5f,bootstrap,172.20.51.114
dhcp-host=00:50:56:b5:d9:ab,master-0,172.20.51.115
dhcp-host=00:50:56:b5:83:7b,master-1,172.20.51.116
dhcp-host=00:50:56:b5:e5:9d,master-2,172.20.51.117
dhcp-host=00:50:56:b5:eb:7b,worker-0,172.20.51.118
dhcp-host=00:50:56:b5:d5:7d,worker-1,172.20.51.119
dhcp-option=option:dns-server,172.20.51.113
dhcp-option=option:netmask,255.255.255.224
dhcp-option=option:router,172.20.51.97
dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases
# 注意etcdj节点名称要与hosts文件中保持一致
srv-host=_etcd-server-ssl._tcp.lab.example.com,etcd-0.lab.example.com,2380,0,10
srv-host=_etcd-server-ssl._tcp.lab.example.com,etcd-1.lab.example.com,2380,0,10 
srv-host=_etcd-server-ssl._tcp.lab.example.com,etcd-2.lab.example.com,2380,0,10 
log-dhcp 
log-facility=/var/log/dnsmasq.log 
conf-dir=/etc/dnsmasq.d
```
### （可选）需要配置访问外网的话
```bash
$ nmcli con modify ens192 ipv4.dns 127.0.0.1 
$ nmcli con down ens192 && nmcli con up ens192 
$ cat <<EOF > /etc/resolv.dnsmasq 
search lab.example.com 
nameserver 172.20.1.142  # 根据环境修改外网DNS服务器地址
EOF
$ systemctl enable --now dnsmasq 
$ systemctl restart dnsmasq
```

## OpenShift相关文件下载和配置
### 创建目录
```bash
$ mkdir -p /ocp/{clients,dependencies,ocp4_install}
$ mkdir -p /ocp/registry/{auth,certs,data,images}
```
### 下载
登陆https://mirror.openshift.com/pub/ 获得指定下载链接，例如4.5.20版本OCP和4.5.6版本CoreOS

#### OCP 4.5.40
```bash
$ cd /ocp/clients
$ wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.5.20/openshift-client-linux.tar.gz
$ wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.5.20/openshift-install-linux.tar.gz
```
#### CoreOS 4.5.6
```bash
$ cd /ocp4_downloads/dependencies
$ wget https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/4.5/4.5.6/rhcos-installer.x86_64.iso
$ wgwt https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/4.5/4.5.6/rhcos-metal.x86_64.raw.gz
```
### 安装 (解压相关文件到系统路径)
`tar xvzf /ocp4_downloads/clients/openshift-client-linux.tar.gz -C /usr/local/bin`

## 创建本地注册镜像
#### 创建证书密钥
```bash
$ cd /ocp/registry/certs
$ openssl req -newkey rsa:4096 -nodes -sha256 -keyout domain.key -x509 -days 3650 -out domain.crt
$ htpasswd -bBc /ocp/registry/auth/htpasswd admin admin
```
#### 创建注册pod
```bash
podman run --name mirror-registry -d -t -p 5000:5000 -v /ocp/registry/data:/var/lib/registry:z -v /ocp/registry/auth:/auth:z -e "REGISTRY_AUTH=htpasswd" -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd -v /ocp/registry/certs:/certs:z -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key docker.io/library/registry:2
```
#### Add certificate to trusted store

```bash
$ cp /ocp/registry/certs/domain.crt /etc/pki/ca-trust/source/anchors/
$ update-ca-trust
```

#### 测试registry是否能正常访问
```bash
$ curl -u admin:admin -k https://localhost:5000/v2/_catalog
# 输出结果应为: {"repositories":[]}
```
#### Create push secret for the registry
```bash
podman login -u "$REGISTRY_USER" -p "${REGISTRY_PASSWORD}" --authfile "${LOCAL_SECRET_JSON}" "${LOCAL_REGISTRY}" 

jq ".auths += ${local_secret_json}" < "${REMOTE_SECRET_JSON}" > "${COMBINED_SECRET_JSON}"
```

### Mirror registry
```bash
# 本地和远端都可以
oc adm -a ${COMBINED_SECRET_JSON} release mirror --from=quay.io/${PRODUCT_REPO}/${RELEASE_NAME}:${OCP_RELEASE} --to=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY} --to-release-image=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}

#涉及很多环境变量，出现问题echo一下
```

保存生成的提示(例如)
```json
imageContentSources:
- mirrors:
  - ZCG:5000/ocp4/openshift4
  source: quay.io/openshift-release-dev/ocp-release
- mirrors:
  - ZCG:5000/ocp4/openshift4
  source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
```
###  extract 创建本地安装程序
```bash
oc adm -a ${COMBINED_SECRET_JSON} release extract --command=openshift-install "${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}" --loglevel=10

cp openshift-install /usr/local/bin/
```

## Bastion - Web Server
```bash
yum install -y epel-release 
yum install -y nginx
vim /etc/nginx/nginx.conf
```

```json
http { 
    server { 
        listen 8008 default_server; # 80->8008 ,80做HA了
    } 
    disable_symlinks off; # 追加 
}
```

```bash
systemctl enable --now nginx
systemctl restart nginx
```

## Generate SSH key for SSH access to cluster nodes

```bash
$ ssh-keygen -t rsa -b 4096 -N ''
$ eval "$(ssh-agent -s)"
$ ssh-add ~/.ssh/id_rsa
```

## Bastion - Load balance

```bash
$ yum install -y haproxy
```
**注意服务器名称，域名，主机名的修改**

```bash
$ cat <<EOF > /etc/haproxy/haproxy.cfg 

frontend K8s-api 
bind *:6443 
option tcplog 
mode tcp 
default_backend api-6443

frontend Machine-config 
bind *:22623 
option tcplog 
mode tcp 
default_backend config-22623 

frontend Ingress-http 
bind *:80 
option tcplog 
mode tcp 
default_backend http-80 

frontend Ingress-https 
bind *:443 
option tcplog 
mode tcp 
default_backend https-443



backend api-6443 
mode tcp 
balance roundrobin 
option ssl-hello-chk 
server bootstrap bootstrap.lab.example.com:6443 check 
server master-0 master-0.lab.example.com:6443 check 
server master-1 master-1.lab.example.com:6443 check 
server master-2 master-2.lab.example.com:6443 check 

backend config-22623 
mode tcp 
balance roundrobin 
server bootstrap bootstrap.lab.example.com:22623 check 
server master-0 master-0.lab.example.com:22623 check 
server master-1 master-1.lab.example.com:22623 check 
server master-2 master-2.lab.example.com:22623 check 

backend http-80 
mode tcp 
balance roundrobin 
server worker-0 worker-0.lab.example.com:80 check 
server worker-1 worker-1.lab.example.com:80 check 

backend https-443 
mode tcp 
balance roundrobin 
option ssl-hello-chk 
server worker-0 worker-0.lab.example.com:443 check 
server worker-1 worker-1.lab.example.com:443 check
EOF
```

```bash
$ systemctl enable --now haproxy 
$ systemctl restart haproxy
```

## 创建`install-config.yaml`安装配置文件

```bash
$ mkdir -p /ibm/installation_directory
$ cd /ibm/installation_directory
$ vim install-config.yaml
```

```yaml
apiVersion: v1
baseDomain: example.com
compute:
- hyperthreading: Enabled
  name: worker
  replicas: 0
controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: 3
metadata:
  name: lab
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
fips: false

# vim ${LOCAL_SECRET_JSON}查看本地pull_secret
pullSecret: '{"auths": {"ZCG:5000":{"auth": "YWRtaW46YWRtaW4="}}}'

# ~/.ssh/id_rsa.pub
sshKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC7Mb1EnG95jx8t56LAO2PNvSHGKyWpVzrmsmj0zqgb6MLamz3L2midA6pFfcm0NVdnnlBeaO3v08+zKRhcg4jttHp9p7be8sXWGoV44QvtKpJcbIXjSYE27/51cWAmNG1izIOX1qu6tmuBKRRvgvPqgD5gK22FDglLgyCFWM5iKURYLa3C83SbREmwko2lzD+51jt36IcmDuP9yd318jwmlrCdVEDE75grdEtBgUwos1cFQRM7eleRtzAsAPy+5MSsirj6Yw0zlqJV7xmffA8tRDZ/N8cTcrDCU9aR9a8N2bD8OixSudCWsJjTJfDNfm/RRLnHuPId0WtPiRdVQ+zheJa60FyI4R5OX3YxokFeet5kCXOS4d8omAFdOpMOeihpE/xtaAVg6W6zWyrDJLmluWk61q5ZZ/Ded0gQXEfDytkjsEHJgIVXzu3i+9Ge4rsuWlHNb88JlPMYO7rl8uhKuykWaLnojpJfqZzYKnfkPtL4qsbEenDyub9d0xBgomHA6fd2PUjLMbZ6YkrA7z9WhXH6GzunCiHWTt2zcHrtd0tGWSFjjFpIP4voqWrEJkZzNPtJw6i9UqyFOEaa+zo87HJOJ7H3zK4lNC3yp+7XSeq/Yz7woYcjyrF1L6Nv5EJiRtzi6KxjpXWsXx5d0YsIV7NGfEMqVC0j552ciwgTdQ== root@ZCG'

# vim /ocp4_downloads/registry/certs/domain.crt
additionalTrustBundle:
  -----BEGIN CERTIFICATE-----
  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
  6ozVln8=
  -----END CERTIFICATE-----

# Mirror registry步骤生成的提示
imageContentSources:
- mirrors:
  - ZCG:5000/ocp4/openshift4
  source: quay.io/openshift-release-dev/ocp-release
- mirrors:
  - ZCG:5000/ocp4/openshift4
  source: quay.io/openshift-release-dev/ocp-v4.0-art-dev

```

```bash
 $ cp install-config.yaml /ibm/install-config.yaml
```

## 生产manifest和.ign文件

### 生产manifest文件

```bash
$ openshift-install create manifests --dir=installation_directory
```

Example output:

*INFO Consuming Install Config from target directory*

*WARNING Making control-plane schedulable by setting MastersSchedulable to true for Scheduler cluster settings*

*For <installation_directory>, specify the installation directory that contains the install-config.yaml file you created.*

Because you create your own compute machines later in the installation process, you can safely ignore this warning.

**Note:**

Modify the <installation_directory>/manifests/**cluster-scheduler-02-config.yml** Kubernetes manifest file to prevent Pods from being scheduled on the control plane machines:

- Open the <installation_directory>/manifests/cluster-scheduler-02-config.yml file.
- Locate the mastersSchedulable parameter and set its value to False.
- Save and exit the file.

## 生成.ign文件
```bash
cd /ibm
openshift-install create ignition-configs --dir=installation_directory
```

## 监控安装进度

```bash
# bootstrap节点
openshift-install --dir=installation_directory wait-for bootstrap-complete --log-level=debug

# cluster
openshift-install --dir=installation_directory wait-for install-complete
```

##  安装boot，master，worker操作系统

将`*.ign`和`rhcosxxx.raw.gz`移动到`usr/share/html`路径下

```bash
/usr/libexec/coreos-installer -d sda -i http://api:8008/bootstrap.ign -b http://api:8008/cos.gz
```

## 批量注册证书

```bash
oc get csr -ojson | jq -r '.items[] | select(.status == {} ) | .metadata.name' | xargs oc adm certificate approve
```

