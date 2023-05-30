## TLS (https) support and ssl termination

To support tls and terminate ssl in the external load balancer created
by the ingress resource, we need to provide certificate to the load balancer
so that:

- it can provide its identity to https clients
- it has a private key to complete the HTTPS handshake

Usually the cert is obtained from a commercial cert authority (CA).
In this example, we use openssl to generate self-signed cert.

Since the client will fetch the cert and verify against the domain (or IP),
the self-signed cert must be created with the domain or IP.

Most SSL/TLS certificates contain a Common Name (CN) and optionally, one or
more Subject Alternative Names (SANs).
The CN (and SANs) identify the domain name(s) that the certificate is valid for
and allow clients to verify that they are connecting to the intended website.

In our case, we need a self-signed cert, there is no domain only an external IP
of the external load balancer. Therefore, we set the CN to the IP, which means
this cert is valid for this IP, and this IP represents the issuer of this cert.

Note: -x509 option means cert and key files are generated in Privacy-Enhanced
Mail (PEM) format. PEM format is required by K8s tls secret creation.

```sh
openssl req -newkey rsa:2048 -nodes -x509 -days 365  \
  -keyout tls.key -out tls.crt \
  -subj "/C=US/ST=PA/L=West Chester/O=BERA/OU=Engr/CN=34.117.165.110"
->
  -keyout tls.key -out tls.crt \
  -subj "/C=US/ST=PA/L=West Chester/O=BERA/OU=Engr/CN=34.117.165.110"
Generating a 2048 bit RSA private key
..............................................................................+++++
........................................+++++
writing new private key to 'tls.key'
```

two files have been created in current folder:

- tls.crt: cert file
- tls.key: private key

Check created cert file

```sh
openssl x509 -in tls.crt -noout -text
```

The cert should be stored in Kubernetes as a Secret object for other resources
to reference.
Use the `kubectl create secret tls` command:

```sh
kubectl create secret tls tls-cert --key tls.key --cert tls.crt
->
secret/tls-cert created

# check created secret
kubectl describe secret tls-cert
```

A secret object named `tls-cert` is created.

Later to update this secret with new crt and key files, we have to extract
its configuration into a yaml manifest, and then use `kubectl apply` to update.

```sh
kubectl create secret generic tls-cert \
--save-config \
--dry-run=client \
--from-file=./tls.key --from-file=./tls.crt \
-o yaml | \
kubectl apply -f -
```

After ingress is deployed using this gke tls secret, we can
check the cert loaded on the site with the IP.
The returned server certificate should have CN with matching IP value:

```sh
openssl s_client -connect 34.117.165.110:443 -showcerts
```
