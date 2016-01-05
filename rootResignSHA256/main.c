#include <openssl/ssl.h>
#include <openssl/x509v3.h>

int add_ext( X509 *issuer, X509 *subj, int nid, const char* value ) {
    X509V3_CTX ctx;

    X509V3_set_ctx( &ctx, issuer, subj, NULL, NULL, 0 );
    X509_EXTENSION *ex = X509V3_EXT_conf_nid( NULL, &ctx, nid, (char *) value );

    if( !ex ) {
        return 0;
    }

    // removing old extensions of the same type
    int loc = -1;
    while( ( loc = X509_get_ext_by_NID(subj, nid, loc) ) != -1 ){
        printf("Removing old extension number %d\n", loc);
        X509_EXTENSION *old = X509_delete_ext(subj, loc);
        X509_EXTENSION_free(old);
    }

    // adding the new extension
    X509_add_ext( subj, ex, -1 );
    X509_EXTENSION_free( ex );

    return 1;
}


int main(int argc, char *argv[]){
    BIO *root = BIO_new_file("root.crt", "r");
    BIO *inter = BIO_new_file("class3.crt", "r");
    BIO *rootkey = BIO_new_file("root.key", "r");
    BIO *outRoot = BIO_new_file("root_256.crt", "w");
    BIO *outInter = BIO_new_file("class3_new.crt", "w");

    X509 *rootCert = PEM_read_bio_X509(root, NULL, 0, NULL);
    BIO_free(root);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(rootkey, NULL, 0, NULL);
    BIO_free(rootkey);
    if (!rootCert || !pkey){
        printf("Reading the keys failed\n");
        return -1;
    }

    // Modifying the Root cert
    if( !add_ext( rootCert, rootCert, NID_crl_distribution_points, "URI:http://crl.cacert.org/revoke.crl" ) ){
        printf("Error while adding extension\n");
        return -1;
    }
    if( !add_ext( rootCert, rootCert, NID_netscape_ca_revocation_url, "URI:http://crl.cacert.org/revoke.crl" ) ){
        printf("Error while adding extension\n");
        return -1;
    }
    if( !add_ext( rootCert, rootCert, NID_info_access, "OCSP;URI:http://ocsp.cacert.org" ) ){
        printf("Error while adding extension\n");
        return -1;
    }
    if( !add_ext( rootCert, rootCert, NID_authority_key_identifier, "keyid" ) ){
        printf("Error while adding extension\n");
        return -1;
    }
    BIGNUM *bn = BN_new();
    
    if(BN_hex2bn(&bn, "0f") == 0) {
        printf("Error while setting Bignum\n");
        return -1;
    }
    BN_to_ASN1_INTEGER( bn , rootCert->cert_info->serialNumber );
    BN_free(bn);
    // End Modifying the Root


    X509_sign(rootCert, pkey, EVP_sha256());
    PEM_write_bio_X509(outRoot, rootCert);
    BIO_free(outRoot);

    printf("Root done, now to intermediate\n");

    X509 *interCert = PEM_read_bio_X509(inter, NULL, 0, NULL);
    BIO_free(inter);
    if (!interCert){
        printf("Reading the Intermediate Certificate\n");
        return -1;
    }

    // Begin Modifying the Intermediate
    if( !add_ext( rootCert, interCert, NID_authority_key_identifier, "keyid" ) ){
        printf("Error while adding extension\n");
        return -1;
    }
    BIGNUM *bnInter = BN_new();

    if(BN_hex2bn(&bnInter, "0e") == 0) {
        printf("Error while setting Bignum\n");
        return -1;
    }
    BN_to_ASN1_INTEGER( bnInter , interCert->cert_info->serialNumber );
    BN_free(bnInter);
    // Begin Modifying the Intermediate

    X509_sign(interCert, pkey, EVP_sha256());
    PEM_write_bio_X509(outInter, interCert);
    BIO_free(outInter);
    X509_free(interCert);

    X509_free(rootCert);
    EVP_PKEY_free(pkey);

    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
    printf("Success\n");
    ERR_free_strings();
    return 0;
}
