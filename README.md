## terraform-ec2-wireproxy

TF to create a localhost [wireproxy](https://github.com/pufferffish/wireproxy) running SOCSK5 and HTTP proxies, egressing an EC2 VM running Wireguard. Also sets up a port-forward to SSH on the VM.

Know what you're deploying; _caveat emptor_.

---

### Requirements:

- `terraform`
- `jq`
- `ssh-add -L` that returns public keys you want configured with the SSH user.

```
$ terraform init \
  && AWS_PROFILE=sandbox terraform apply --auto-approve \
  && wireproxy -c wireproxy.conf
```

```
$ curl --socks5 127.0.0.1:1080 -i https://checkip.amazonaws.com
```

```
$ curl -x 127.0.0.1:1081 -i https://checkip.amazonaws.com
```

```
$ ssh whoami@localhost -p 1122
```

```
$ terraform destroy
```
