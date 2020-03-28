# DecentRaVerif
Verification of the Decent RA protocol, by using the ProVerif verification tool.

## Process Overview
The following figure shows that we modeled DecentRA framework with 6 different processes.
![Process Overview](README-src/ProcOverview.svg)

The next figure shows that the honest process is splited into an infinite replication of IAS processes, and an infinit replication of enclave platforms. Each enclave platform creates its own local report key, and further splits the process into infinit replication of Decent Servers and Decent Apps.
![Process Overview - More Details](README-src/ProcOverview-detailed.svg)

## Adversarial Model

* We assume
	* the correctness of all existing cryptographic algorithms (e.g. hash, DSA, DHKE)
	* the enclave platform is not compromised

* Attackers may not
	* access the private IAS report key, provisioning key, and local report key
	* access any private key held by a legitimate enclave
	* alter the behavior of the enclave

* Attackers may
	* know the behavior of the enclave
	* control all message channels
	* create their own Decent Apps or Decent Servers, and access their private keys
	* access the private keys held by revoked Decent Apps
