# Idam - Identity and Access Management

`Idam` is an identity and access management platform designed for `homebot`.

## Design

### Authentication

Like everything in `Homebot`, each identity has a unique resource name (URN) and can either represent a service or user account. Such an identity can authenticate at the IDAM gRPC server using it's password/secret and optional a time-based one-time-password (TOTP). Once authenticated the IDAM server issues a signed JSON Web Token to the identity containing the identity's URN (subject), a list of groups as well as the JWT standard claims with issuer (the URN of the IDAM server), expire-at and issued-at dates. Whenever the identity interacts with another Homebot service, the JWT should be included in the request (e.g. `Authorization` header for HTTP and HTTP2/gRPC). Just before the JWT expires, the idenity can request a new JWT token by re-authenticating at the IDAM server (if the token is still valid, password and OTP are not required).

## Authorization

In future, a RBAC (Role-based access control) or ABAC (Attribute-based access control) will be implemented. To be designed ...