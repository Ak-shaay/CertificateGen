from cryptography.x509 import CertificateBuilder
from cryptography.x509 import Name, NameAttribute, AuthorityKeyIdentifier, SubjectKeyIdentifier,AuthorityInformationAccess, AccessDescription,IssuerAlternativeName
from cryptography.x509 import KeyUsage, CertificatePolicies, BasicConstraints, ExtendedKeyUsage, CRLDistributionPoints,PolicyInformation
from cryptography.x509.oid import NameOID, ExtensionOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509 import CRLDistributionPoints, DistributionPoint, UniformResourceIdentifier,UnrecognizedExtension,DNSName,RFC822Name,IPAddress,NameConstraints
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ObjectIdentifier, Extension
from ipaddress import IPv4Network, IPv6Network


import datetime

# Function to generate a new RSA private key
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key

# Function to generate the certificate (without signing)
def generate_certificate(private_key, subject_details, oid_dict=None, cert_type="end_entity"):
    public_key = private_key.public_key()

    # Create the subject (who this certificate is for)
    subject = Name([
        NameAttribute(NameOID.COUNTRY_NAME, subject_details['C']),
        NameAttribute(NameOID.ORGANIZATION_NAME, subject_details['O']),
        NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_details['OU']),
        NameAttribute(NameOID.COMMON_NAME, subject_details['CN']),
        NameAttribute(NameOID.LOCALITY_NAME, subject_details['L']),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_details['ST']),
        NameAttribute(NameOID.POSTAL_CODE, subject_details['postalCode']),
    ])

    # issuer details
    issuer = subject

    # Validity period
    not_valid_before = datetime.datetime.utcnow()
    not_valid_after = not_valid_before + datetime.timedelta(days=3650)

    # Build the certificate
    cert_builder = CertificateBuilder(
        subject_name=subject,
        issuer_name=issuer,
        public_key=public_key,
        serial_number=1000,
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after
    )

    # Add OIDs and their values (if provided)
    if oid_dict:
        for oid, value in oid_dict.items():
            cert_builder = cert_builder.add_extension(
                ExtensionOID(oid), True, value
            )

  

    # # Authority Key Identifier
    cert_builder = cert_builder.add_extension(
        AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            SubjectKeyIdentifier.from_public_key(public_key)
        ), critical=False
    )

    # Subject Key Identifier
    cert_builder = cert_builder.add_extension(
        SubjectKeyIdentifier.from_public_key(public_key), critical=False
    )

    # Add AuthorityInformationAccess extension to the certificate
    cert_builder = cert_builder.add_extension(
    AuthorityInformationAccess([  # Using the custom AuthorityInformationAccess class
        AccessDescription(
            # ExtensionOID.AUTHORITY_INFORMATION_ACCESS,  # Access Method, in this case, it is defined by the OID
            ObjectIdentifier("1.3.6.1.5.5.7.48.1"),
            UniformResourceIdentifier("http://example.com/aia")  # Example OCSP URL (Access Location)
        )
    ]),
    critical=False  # Make the extension non-critical
    )

    # Key Usage
    if cert_type == "ca":
        # CA Certificates
        cert_builder = cert_builder.add_extension(
            KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True, 
                crl_sign=True,      
                decipher_only=False,
                encipher_only=False
            ),
            critical=True
        )
    elif cert_type == "end_entity":
        # End Entity Certificates
        cert_builder = cert_builder.add_extension(
            KeyUsage(
                digital_signature=True,        # End Entity cert must have digitalSignature
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,           # End Entity cert must NOT have keyCertSign
                crl_sign=False,                # End Entity cert must NOT have crlSign
                decipher_only=False,
                encipher_only=False
            ),
            critical=True
        )

    # CRL Distribution Points
    crl_url = "http://crl-example.com/revocation/crl.crl"

    crl_distribution_point = UniformResourceIdentifier(crl_url)

    distribution_point = DistributionPoint(
        full_name=[crl_distribution_point],  
        relative_name=None,  
        reasons=None,  
        crl_issuer=None  
    )

    crl_extension = CRLDistributionPoints([distribution_point])

    cert_builder = cert_builder.add_extension(
        crl_extension,  
        critical=False 
    )

    #certificate policies

    policy_identifier = ObjectIdentifier("1.2.840.113549.1.9.1")  # Example policy OID
    policy_qualifier = "Example Policy Qualifier"  # Can also be a UserNotice object

    policy_info = PolicyInformation(
        policy_identifier=policy_identifier,
        policy_qualifiers=[policy_qualifier]
    )

    certificate_policies_extension = CertificatePolicies([policy_info])

    cert_builder = cert_builder.add_extension(
        # ExtensionOID.CERTIFICATE_POLICIES,
        certificate_policies_extension,
        critical=False
    )

    # poison Extension
    poisonExtInput = input("Do you want to add poison extension (y/n)").strip()

    if poisonExtInput == 'y':
        poisonExtOID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
        poisonExtValue = "poison extension"
        encodedPoisonExtValue = poisonExtValue.encode("utf-8")

        poisonExtension = UnrecognizedExtension(
            poisonExtOID,
            encodedPoisonExtValue
        )
        cert_builder = cert_builder.add_extension(poisonExtension,critical=True)

    #issuer Alternate Name
    ianInput = input("Do you want to add Issuer Alternate Name (y/n)").strip()

    if ianInput == 'y':
        # Create specific GeneralName objects
        dns_name = DNSName("example.com")
        email_address = RFC822Name("issuer@example.com")

        ian_extension = IssuerAlternativeName([dns_name,email_address])

        cert_builder = cert_builder.add_extension(ian_extension, critical=False)

    # Name Constraints
    ncInput = input("Do you want to add Name Constraints (y/n): ").strip()

    if ncInput == 'y':
        # Collect the permitted subtrees
        permitted_input = input("Do you want to add permitted subtrees (y/n): ").strip()
        permitted_subtrees = []
        if permitted_input == 'y':
            # Example of creating GeneralName objects for permitted subtrees
            # Create DNSName and IPAddress objects
            dns_name_permitted = DNSName("permitted.example.com")
            ip_address_permitted = IPAddress(IPv4Network("192.168.0.0/24"))
            permitted_subtrees = [dns_name_permitted, ip_address_permitted]

        # Collect the excluded subtrees
        excluded_input = input("Do you want to add excluded subtrees (y/n): ").strip()
        excluded_subtrees = []
        if excluded_input == 'y':
            # Example of creating GeneralName objects for excluded subtrees
            # Create DNSName and IPAddress objects
            dns_name_excluded = DNSName("excluded.example.com")
            ip_address_excluded = IPAddress(IPv6Network("2001:db8::/32"))
            excluded_subtrees = [dns_name_excluded, ip_address_excluded]

        # Create the NameConstraints object
        name_constraints_extension = NameConstraints(
            permitted_subtrees=permitted_subtrees if permitted_subtrees else None,
            excluded_subtrees=excluded_subtrees if excluded_subtrees else None
        )

        # Add the NameConstraints extension to the certificate builder
        cert_builder = cert_builder.add_extension(name_constraints_extension, critical=False)


    #custom OID generation
    my_custom_oid = ObjectIdentifier("1.20.30.40.50.60.7")
    custom_value = "my_custom_data"
    encoded_value = custom_value.encode("utf-8") 

    custom_extension = UnrecognizedExtension(
        my_custom_oid, 
        encoded_value  
    )

    cert_builder = cert_builder.add_extension(custom_extension, critical=False)



    # Basic Constraints (CA certificate)
    if cert_type == "ca":
        ccaInput = input("Is this a CCA certificate (y/n)?").strip().lower()
        if ccaInput == 'y':
            cert_builder = cert_builder.add_extension(
                BasicConstraints(ca=True, path_length=None), critical=True
            )
        else:
            cert_builder = cert_builder.add_extension(
                BasicConstraints(ca=True, path_length=0), critical=True
            )
    else:
        cert_builder = cert_builder.add_extension(
            BasicConstraints(ca=False, path_length=None), critical=True
        )

    # Initialize the key usages list with some OIDs
    key_usages = []

    # Ask user for Server Authentication preference
    serverAuth = input("Server Authentication (y/n): ").strip().lower()
    if serverAuth == 'y' and ObjectIdentifier("1.3.6.1.5.5.7.3.1") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.5.5.7.3.1"))  # Server Authentication OID

    # Ask user for Client Authentication preference
    clientAuth = input("Client Authentication (y/n): ").strip().lower()
    if clientAuth == 'y' and ObjectIdentifier("1.3.6.1.5.5.7.3.2") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.5.5.7.3.2"))  # Client Authentication OID

    # Ask user for Code Signing preference
    codeSigning = input("Code Signing (y/n): ").strip()
    if codeSigning == 'y' and ObjectIdentifier("1.3.6.1.5.5.7.3.3") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.5.5.7.3.3"))  # Code Signing OID

    # Ask user for Email Protection preference
    emailProtection = input("Email Protection (y/n): ").strip().lower()
    if emailProtection == 'y' and ObjectIdentifier("1.3.6.1.5.5.7.3.4") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.5.5.7.3.4"))  # Email Protection OID

    # Ask user for OCSP Signing preference
    ocspSigning = input("OCSP Signing (y/n): ").strip().lower()
    if ocspSigning == 'y' and ObjectIdentifier("1.3.6.1.5.5.7.3.9") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.5.5.7.3.9"))  # OCSP Signing OID

    # Ask user for Timestamping preference
    timestamping = input("Timestamping (y/n): ").strip().lower()
    if timestamping == 'y' and ObjectIdentifier("1.3.6.1.5.5.7.3.8") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.5.5.7.3.8"))  # Timestamping OID

    # Ask user for Smart Card Logon preference
    smartCardLogon = input("Smart Card Logon (y/n): ").strip().lower()
    if smartCardLogon == 'y' and ObjectIdentifier("1.3.6.1.4.1.311.20.2.2") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"))  # Smart Card Logon OID

    # Ask user for MSFT Document Signing preference
    msftDocSigning = input("MSFT Document Signing (y/n): ").strip().lower()
    if msftDocSigning == 'y' and ObjectIdentifier("1.3.6.1.4.1.311.10.3.12") not in key_usages:
        key_usages.append(ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"))  # MSFT Document Signing OID

    # Ask user for Adobe Certified Document Signing preference
    adobeDocSigning = input("Adobe Certified Document Signing (y/n): ").strip().lower()
    if adobeDocSigning == 'y' and ObjectIdentifier("1.2.840.113583.1.1.5") not in key_usages:
        key_usages.append(ObjectIdentifier("1.2.840.113583.1.1.5"))  # Adobe Certified Document Signing OID

    addExtraInput = input("Add extra keyUsages (y/n): ").strip().lower()

    while addExtraInput == 'y':  # Loop runs while user wants to add extra key usages
        oid = input("Enter your OID: ").strip()
        key_usages.append(ObjectIdentifier(oid))  # Append the entered OID to the list

        # Ask again if the user wants to add more
        addExtraInput = input("Add another extra keyUsage (y/n): ").strip().lower()


    # Create the certificate builder and add the extended key usage extension
    cert_builder = cert_builder.add_extension(
        ExtendedKeyUsage(key_usages), critical=False
    )


    return cert_builder

# Function to parse the OIDs input from the user
def parse_oids_input():
    oid_dict = {}
    while True:
        oid = input("Enter OID (or 'n' to finish): ").strip()
        if oid.lower() == 'n':
            break
        value = input(f"Enter value for OID {oid}: ").strip()
        oid_dict[oid] = value
    return oid_dict

# Function to self sign the certificate
def self_sign_certificate(cert_builder, private_key):
    return cert_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )

# Function to save the certificate to a PEM file
def save_certificate_to_pem(certificate, filename):
    with open(filename, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

# Function to save the private key to a PEM file
def save_private_key_to_pem(private_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def main():
    # Ask the user for certificate details
    # subject_details = {
    #     'CN': input("Enter common name (CN): ").strip(),
    #     'O': input("Enter organization (O): ").strip(),
    #     'OU': input("Enter organizational unit (OU): ").strip(),
    #     'C': input("Enter country (C): ").strip(),
    #     'L': input("Enter locality (L): ").strip(),
    #     'ST': input("Enter state (ST): ").strip(),
    #     'postalCode': input("Enter postal code (P): ").strip()
    # }
    subject_details = {
        'CN': "CCA India 2025",
        'O': "India PKI",
        'OU': "Certifying Authority",
        'C': "IN",
        'L': "Bangalore",
        'ST': "Karnataka",
        'postalCode': "560100"
    }

    # Ask user whether it's a CA or end entity certificate
    cert_type_input = input("Is this a CA certificate (y/n): ").strip().lower()
    if cert_type_input == 'y':
        cert_type = 'ca'
    elif cert_type_input == 'n':
        cert_type = 'end_entity'
    else:
        print("Invalid input. Defaulting to 'end_entity'.")
        cert_type = 'end_entity'

    # Validate cert_type
    if cert_type not in ['ca', 'end_entity']:
        print("Invalid certificate type. Please enter either 'ca' or 'end_entity'.")
        return

    # Generate the private key for the new certificate
    private_key = generate_private_key()

    # Parse OIDs and values for the new certificate
    print("You can add custom OIDs (Object Identifiers) and their values.")
    oid_dict = parse_oids_input()

    # Generate the certificate (without signing)
    cert_builder = generate_certificate(private_key, subject_details, oid_dict, cert_type)

    # Sign the certificate
    signed_certificate = self_sign_certificate(cert_builder, private_key)

    # Save the signed certificate and private key
    save_certificate_to_pem(signed_certificate, "Root_"+cert_type.upper()+".cer")
    save_private_key_to_pem(private_key, "Root_"+cert_type.upper()+"_key.pem")

    print("Signed certificate and private key have been saved.")

if __name__ == "__main__":
    main()
