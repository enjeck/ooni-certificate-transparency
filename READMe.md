# Ooni data + Certificate Transparency

The [OONI project](https://ooni.org/) makes HTTPS connections to various websites from “probes” around the world to monitor internet censorship. They produce a [“webconnectivity” dataset](https://ooni.org/post/mining-ooni-data) with measurements that include the [X.509 certificate](https://en.wikipedia.org/wiki/X.509) chains they observe.

[Certificate Transparency](https://certificate.transparency.dev/) is a system that collects publicly trusted X.509 certificates for auditing, monitoring, and analysis. It would be nice to make sure that every certificate chain observed by OONI ends up in Certificate Transparency.

This program fetches JSONL files from the [OONI S3 bucket](https://ooni-data-eu-fra.s3.eu-central-1.amazonaws.com/), extracts certificate chains and submit them to [Let’s Encrypt testing Twig logs](https://letsencrypt.org/docs/ct-logs/#Sunlight). It is possible to run the program periodically (e.g. every day, as a cron job) and it can resume from where it left off.

## Running the code
To run it locally:
- Clone this repo and change into the directory
- Create a Python virtual environment and activate it
- Install the required dependencies using pip: `pip install -r requirements.txt`
- Run the script: `python chain.py`. 

I imagine this being deployed in a self-managed server like AWS EC2 with a Linux operating system like Ubuntu. There, we can create a cron job that launches the script periodically.  

## Resuming
The values in [state.json](/state.json) specify the time periods that will be considered when selecting which OONI webconnectivity files to extract certificate chains from. The dates are modifiable. By default, the end date is not specified, so the script will use data from the start date until the current day. The start date is updated while the script runs to keep track of where to start from next time in case the script is stopped and re-run later. 

## Possible Improvements
- Unit tests for most of the functions.
- The function `hasValidDates` that checks if a certificate chain is expired, and does not submit the chain if it is because it will be rejected. But this function appears to buggy, since I still get a lot rejected requests of the form `invalid chain: certificate NotAfter (2024-08-28 23:59:59 +0000 UTC) >= 2024-07-20 00:00:00 +0000 UTC`. I'm obviously missing something, and would like to figure out what.
- After fetching a single file from S3, it is processed first before moving onto the next. This processing period is quite lengthy, so there's no need to rate-limit this part. Right now, all the "rate-limiting" I do is just waiting for 5 seconds after submitting a chain via a request to `twig.ct.letsencrypt.org/2024h1/ct/v1/add-chain` before trying the next. This is not effective because we wait even in cases where a request isn't made due to the chain being predetermined as invalid. It would be nice to have real rate-limiting algorithm.
- Majority of the code run time is spent waiting (downloading, sending a request to add a chain). I believe this presents an opportunity to do tasks concurrently to speed everything up. 
- To avoid making unnecessary requests to add a certificate chain, we can avoid sending chains that would be rejected. There are several conditions that could be checked to ensure a chain is valid such as:
    - _Trust_: Verify that the root certificate is trusted by checking if it is included in a list of trusted root CAs. Not sure where to get such an updated list from, and couldn't find a library that does it. 
    - _Expiry_: Verify that none of the certificates in the chain have expired by comparing the current date with the validity period specified in each certificate (Implemented in `hasValidDates`)
    - _Revocation_: Check the revocation status of each certificate in the chain by checking any Certificate Revocation Lists. Not sure where to get updated lists from
    - _Completeness_: Ensure that the certificate chain is complete by verifying that all intermediate certificates are included in the chain. I believe we can do this by checking the issuer field of each certificate and ensuring that it matches the subject field of the next certificate in the chain. (Implemented in `isCompleteChain`)
    - _Check Order_: Verify that the certificates are ordered correctly, with the server certificate first, followed by any intermediate certificates, and finally the root certificate.
    - _Check Encoding and Format_: Validate the format of each certificate to ensure they are comptible with the X.509 standard.
