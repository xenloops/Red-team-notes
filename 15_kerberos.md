# Kerberos

When a user logs onto their workstation it sends an AS-REQ to the Key Distribution Center (KDC)/Domain Controller (DC), requesting a TGT using a secret key derived from the user's password. KDC verifies the secret key with the password it has stored in Active Directory for that user. If valid it returns the TGT. The TGT contains the user's identity and is encrypted with the KDC secret key (the krbtgt account). When the user attempts to access a resource using Kerberos (e.g. a file share), the client looks up the associated Service Principal Name (SPN), and requests a Ticket Granting Service Ticket (TGS) for that service from the KDC, and presents its TGT as a means of proving they're valid. The KDC returns a TGS for the service, which is then presented to the actual service. The service inspects the TGS and decides whether it should grant the user access.

| Client | | KDC | | Server |
|:--:|:--:|:--:|:--:|:--:|
| Request TGT (AS-REQ) | -> | • | | |
| • | <- | Return TGT (AS-REP) |  |  |
| Request TGS for service (TGS-REQ) | -> | • | | |
| • | <- | Return TGs (TGS-REP) |  |  |
| Present TGS to service | -> | -> | -> | • |
| • | <- | <- | <- | Grant access |


