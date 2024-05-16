from cryptography import x509
import base64
import requests
import boto3
from botocore import UNSIGNED
from botocore.client import Config
import os
import datetime
import jsonlines
import gzip
import time
import shutil
from typing import List, Dict


# The state_file should be a json line file with the format like:
# {"start": {"date": "2024-05-05", "hour": 0}, "end": {"date": "2024-05-15", "hour": 0}}
# " date" is a string with format "YYYY-MM-DD" and "hour" is a number from 0 - 23 inclusive
state_file = "./state.json"      

s3_bucket = "ooni-data-eu-fra"
s3_client = boto3.client("s3", config=Config(signature_version=UNSIGNED))
data_folder = './data'
already_seen_server_names = set()
chain_destination = "https://twig.ct.letsencrypt.org/2024h1/ct/v1/add-chain"    


# Reference: https://datatracker.ietf.org/doc/html/rfc6962#section-4.1
# POST https://<log server>/ct/v1/add-chain
#    Inputs:
#       chain:  An array of base64-encoded certificates.  The first
#          element is the end-entity certificate; the second chains to the
#          first and so on to the last, which is either the root
#          certificate or a certificate that chains to a known root
#          certificate.
# Outputs:
#       sct_version:  The version of the SignedCertificateTimestamp
#          structure, in decimal
#       id:  The log ID, base64 encoded.
#       timestamp:  The SCT timestamp, in decimal.
#       extensions:  An opaque type for future expansion.
#       signature:  The SCT signature, base64 encoded.
def submitCertChain(chain: List[str]) -> None:
    # Using [Let's Encrypt Twig logs](https://letsencrypt.org/docs/ct-logs/#Sunlight): 
    data_to_submit = {"chain": chain}
    
    print("adding chain...")
    res: requests.Response = requests.post(chain_destination, json=data_to_submit)
    if res.status_code == 200:
        print("Chain added: " + res.text, '\n')
    else:
        print("Failed to add chain: " + res.text)
    # Naive rate-limiting by just waiting for 5 seconds after each attempt
    time.sleep(5) 


# We check that the certificate chain is complete by verifying that all necessary intermediate certificates are included in the chain. We do this by checking the issuer field of each certificate and ensuring that it matches the subject field of the next certificate in the chain.
def isCompleteChain(x509_certs: List[x509.Certificate]) -> bool:
    prev_cert_issuer = x509_certs[0].issuer
    for cert in x509_certs[1:]:
        if cert.subject != prev_cert_issuer:
            return False
        prev_cert_issuer = cert.issuer
    return True


# Reference: [Section 4.1.2.5. of RFC 5280](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5):
# Validity
# The certificate validity period is the time interval during which the
# CA warrants that it will maintain information about the status of the
# certificate. The field is represented as a SEQUENCE of two dates:
# the date on which the certificate validity period begins (notBefore)
# and the date on which the certificate validity period ends
# (notAfter).
def hasValidDates(x509_certs: List[x509.Certificate]) -> bool:
    for x509_cert in x509_certs:
        today = datetime.datetime.today()
        not_before_date = x509_cert.not_valid_before_utc.replace(tzinfo=None)
        not_after_date = x509_cert.not_valid_after_utc.replace(tzinfo=None)
        if today < not_before_date or today > not_after_date:
            return False
    return True

def getX509Certs(base64_certs: List[str]) -> List[x509.Certificate]:
    x509_certs = []
    for base64_cert in base64_certs:
        cert_data = base64_cert.encode()
        cert_byte_data = base64.b64decode(cert_data)

        # Gives an X.509.Certificate object containing certain properties
        # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object
        cert: x509.Certificate = x509.load_der_x509_certificate(cert_byte_data)
        x509_certs.append(cert)
    return x509_certs

def isValidChain(base64_certs: List[str]) -> bool:
    x509_certs = getX509Certs(base64_certs)
    return hasValidDates(x509_certs) and isCompleteChain(x509_certs)

# Reference: OONI's documentation about how data is strutured:
# - https://github.com/ooni/spec/blob/master/data-formats/df-006-tlshandshake.md
# - https://github.com/ooni/spec/blob/master/data-formats/df-001-httpt.md
# peer_certificates is a list of peer certificates in ASN.1 DER format represented using the `BinaryData` {"format": "base64", "data": "AQI="}
# - format (string): MUST be base64.
# - data (string): the base64 representation of the value that we could not represent using UTF-8.
def processCerts(peer_certificates: List[Dict[str, str]]) -> None:
    if not peer_certificates:
        return
    formatted_certs = []
    for cert in peer_certificates:
        cert_data = cert["data"]
        # remove illegal characters
        data = base64.b64encode(base64.b64decode(cert_data))
        data = data.decode("utf-8")
        formatted_certs.append(data)
    if isValidChain(formatted_certs):
        submitCertChain(formatted_certs)
        
def fetchAndProcessData(files_object):
    print("Fetching and processing jsonl files...")
    for file_object in files_object:
        if file_object["Key"].endswith("jsonl.gz"):
            file_path = file_object["Key"]
            file_name = file_path.split("/")[-1]
            p = os.path.join("./data", file_name)
            path_extracted = os.path.join("./data", file_name + ".jsonl")
            try:
                s3_client.download_file(Bucket=s3_bucket, Key=file_object["Key"], Filename=p)
                with gzip.open(p, "rb") as f_in:
                    with open(path_extracted, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
            except Exception as e:
                print(f"Error downloading file: {e}")

            # Reference for data structure: https://github.com/ooni/spec/blob/master/data-formats/df-006-tlshandshake.md?plain=1
            with jsonlines.open(path_extracted) as reader:
                for obj in reader:
                    tls_handshakes = obj["test_keys"]["tls_handshakes"]
                    if tls_handshakes:
                        for handshake in tls_handshakes:
                            # peer_certificates hold the certificate chain in an array. With peer_certificates[0] being the end-entity certificate, peer_certificates[last] the root Certificate and
                            # everything in-between being the intermediate certs
                            peer_certificates = handshake["peer_certificates"]
                            
                            server_name = handshake["server_name"]
                            
                            # Skip certificates that we have seen before
                            if server_name in already_seen_server_names: 
                                continue
                            
                            already_seen_server_names.add(server_name)
                            processCerts(peer_certificates)


def fetchPathsFromS3(time_period: str) -> List[str]:
    print("Fetching file paths for: ", time_period)
    list_files = s3_client.list_objects_v2(
        Bucket=s3_bucket, Prefix=time_period, Delimiter="/"
    )
    country_paths = []
    if "CommonPrefixes" in list_files:
        country_prefixes = list_files["CommonPrefixes"]
        country_paths = [prefix["Prefix"] for prefix in country_prefixes]
    return country_paths


def processOoniData(date: str, hour: str) -> None:
    date: str = "".join(date.split("-"))
    if len(hour) < 2:
        hour = "0" + hour
    country_paths = fetchPathsFromS3("raw/" + date + "/" + hour + "/")
    for country in country_paths[:1]:
            # Reset the set for each date/hour/country combination
            # such that the duplicate check works properly
            already_seen_server_names = set()  
            path = country + "webconnectivity/"
            files_object = s3_client.list_objects_v2(
                Bucket=s3_bucket, Prefix=path, Delimiter="/"
            )["Contents"]
            print("Processing for: ", {"date": date, "hour": hour, "country": country})
            fetchAndProcessData(files_object)

# After processing and submiting data, there's no need to keep the JSON data stored, so we delete it to save space
def cleanUp() -> None:
    for filename in os.listdir(data_folder):
        file_path = os.path.join(data_folder, filename)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(f"Error deleting {file_path}: {e}")


def saveNextStartState(
    start_date: str, end_date: str, start_hour: int, end_hour: int
) -> None:
    data = {
        "start": {"date": start_date, "hour": start_hour},
        "end": {"date": end_date, "hour": end_hour},
    }
    with jsonlines.open(state_file, mode="w") as writer:
        writer.write(data)
    print("Saved checkpoint state: ", data)


def convertToDatetime(date_string: str, hour: int):
    try:
        # Assuming the input date string is in the format "YYYY-MM-DD"
        date_object = datetime.datetime.strptime(date_string, "%Y-%m-%d")
        date_with_hour = date_object.replace(hour=hour)
        return date_with_hour
    except ValueError:
        print("Invalid date")
        return None

def loadState() -> None:
    print("Loading state...")
    with jsonlines.open(state_file) as reader:
        for obj in reader:
            start_date = obj["start"]["date"]
            start_hour = obj["start"]["hour"]
            end_date = obj["end"]["date"]
            end_hour = obj["end"]["hour"]
        print("State loaded: ", obj)
        return [start_date, end_date, start_hour, end_hour]

def run():
    ooni_earliest_datetime = convertToDatetime("2020-10-20", 0)
    today_datetime = datetime.datetime.now()

    start_date, end_date, start_hour, end_hour = loadState()

    if not (start_date or end_date or start_hour or end_hour):
        print("Valid period not provided")
        return
    start_datetime = convertToDatetime(start_date, int(start_hour))
    end_datetime = (
        end_date
        if convertToDatetime(end_date, int(end_hour))
        else today_datetime
    )
    if end_datetime > today_datetime or start_datetime < ooni_earliest_datetime:
        print("No data available for this date: ", {"start_datetime": start_datetime, "end_datetime": end_datetime })

    current_datetime = start_datetime
    
    # Runs until we surpass the current time or until script is cancelled (Ctrl + C)
    while True:
        dt = current_datetime.strftime("%Y-%m-%d %H")
        date, hour = dt.split(" ") # (YYYY, HH)
        processOoniData(date, hour)
        
        # stop at the current day and hour since there's no data beyond this
        if current_datetime > end_datetime:
            print("Finished!")
            return
        
        current_datetime = (current_datetime + datetime.timedelta(hours=1))
        next_date, next_hour = (current_datetime.strftime("%Y-%m-%d %H")).split(" ") # (YYYY, HH)
        
        # after processing, we save the date and hour, so we can continue whenever the script is re-run
        saveNextStartState(next_date, end_date, int(next_hour), end_hour)
        cleanUp()
        

# Starts the process
run() 
