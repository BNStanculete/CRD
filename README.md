# Cloud Networking Research Project

In this research project we will run a simulation with four hosts that are co-resident:
- h1 is a Django HTTP server connected to an SQLITE databse
- h2 is the adversary that is testing for co-residency
- h3 and h4 are normal HTTP clients

## Topology

Switch s1 is connected to hosts on the following ports:
- s2 port 1
- h1 port 2
- h2 port 3
- h3 port 4

Switch s2 is connected to hosts on the following ports:
- s1 port 1
- h4 port 2
- h5 port 3
