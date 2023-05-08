# dothole

A DNS over TLS recursive name server, inspired by [Pi-hole](https://pi-hole.net/)

## Features:
1. DNS over TLS for both the client and the upstream server
2. caching entries
3. blocklists
4. injecting results
5. prometheus server displaying statistics, by default at https://localhost:8080/metrics


## Testing:
Ensure you have a public private keypair saved to cert.pem and key.pem

Run the server with: `go run proxy.go`

Test if it is working with: `dig +tls @0.0.0.0 -p 5353 gnu.org`, changing the IP address after @ as appropriate
