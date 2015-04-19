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
    BIO *rootkey = BIO_new_file("root.key", "r");
    BIO *out = BIO_new_file("root_256.crt", "w");

    X509 *cert = PEM_read_bio_X509(root, NULL, 0, NULL);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(rootkey, NULL, 0, NULL);
    if (!cert || !pkey){
        printf("Reading the keys failed\n");
        return -1;
    }
    if( !add_ext( cert, cert, NID_crl_distribution_points, "URI:http://crl.cacert.org/revoke.crl" ) ){
        printf("Error while adding extension\n");
        return -1;
    }
    X509_sign(cert, pkey, EVP_sha256());

    PEM_write_bio_X509(out, cert);
    
    BIO_free(root);
    BIO_free(rootkey);
    BIO_free(out);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    ERR_load_crypto_strings();
    ERR_print_errors_fp(stdout);
    printf("Success\n");
    ERR_free_strings();
    return 0;
}
