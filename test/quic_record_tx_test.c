#include <openssl/ssl.h>
#include "testutil.h"
#include "internal/quic_record_tx.h"
#include "internal/bio_addr.h"
#include "helpers/quictestlib.h"

static OSSL_QRL_ENC_LEVEL_SET test_el_set;

static int test_ossl_qtx_write_pkt(void)
{
    OSSL_QTX *qtx = NULL;
    OSSL_QTX_PKT pkt = {0};
    QUIC_PKT_HDR hdr = {0};
    const unsigned char secret[32] = {0};
    size_t mdpl = QUIC_MIN_INITIAL_DGRAM_LEN;

    qtx = qtest_create_qtx_with_default_el_set(mdpl, &test_el_set);
    if (!TEST_ptr(qtx))
        goto err;

    if (!TEST_true(qtest_provide_secret(qtx, QUIC_ENC_LEVEL_INITIAL,
                                        EVP_sha256(), secret, sizeof(secret))))
        goto err;

    hdr.type = QUIC_PKT_TYPE_INITIAL;
    pkt.hdr = &hdr;

    for (size_t i = 0; i < 10; ++i) {
        if (!TEST_true(ossl_qtx_write_pkt(qtx, &pkt)))
            goto err;
    }

    size_t new_mdpl = mdpl + 100;
    if (!TEST_true(ossl_qtx_set_mdpl(qtx, new_mdpl)))
        goto err;

    if (!TEST_true(ossl_qtx_write_pkt(qtx, &pkt)))
        goto err;

    ossl_qtx_free(qtx);
    return 1;

err:
    ossl_qtx_free(qtx);
    return 0;
}

int setup_tests(void)
{
    ADD_TEST(test_ossl_qtx_write_pkt);
    return 1;
}
