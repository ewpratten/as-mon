# ASN Monitoring

This repository contains a script that sends me a daily report about exposed services on all known hosts inside AS54041.

## How it works

1. Query a certain `route-set` to determine which prefixes should be checked
2. Dump all PTR records from Cloudflare that are in the corresponding zones for the prefixes from step 1
3. Perform some network and DNS scans against the IPs
4. Report the results via an email to NOC

## Running

The following environment variables must be passed through to the docker container:

- `SENDGRID_API_KEY`: API key for SendGrid
- `CLOUDFLARE_TOKEN`: Cloudflare token with read access to all zones
- `NOTIFICATION_EMAIL_SOURCE`: Email address to send the report from
- `NOTIFICATION_EMAIL_DEST`: Email address to send the report to
- `TARGET_ROUTE_SET`: Route set to query for prefixes
- `ASN`: The network ASN

Then, run the container:

```bash
docker run --rm -e SENDGRID_API_KEY -e CLOUDFLARE_TOKEN -e NOTIFICATION_EMAIL_SOURCE -e NOTIFICATION_EMAIL_DEST -e TARGET_ROUTE_SET -e ASN ewpratten/as-mon:latest
```
