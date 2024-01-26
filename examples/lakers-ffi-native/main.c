#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lakers_shared.h"
#include "lakers_ead_authz.h"
#include "lakers_ffi.h"
#include <coap3/coap.h>
#include <arpa/inet.h>

static const uint8_t ID_U[] = {0xa1, 0x04, 0x41, 0x2b};
static const uint8_t ID_U_LEN = sizeof(ID_U) / sizeof(ID_U[0]);

static const BytesP256ElemLen G_W = {0xFF, 0xA4, 0xF1, 0x02, 0x13, 0x40, 0x29, 0xB3, 0xB1, 0x56, 0x89, 0x0B, 0x88, 0xC9, 0xD9, 0x61, 0x95, 0x01, 0x19, 0x65, 0x74, 0x17, 0x4D, 0xCB, 0x68, 0xA0, 0x7D, 0xB0, 0x58, 0x8E, 0x4D, 0x41};

static const uint8_t LOC_W[] = {0x6, 0x3, 0x6, 0xf, 0x6, 0x1, 0x7, 0x0, 0x3, 0xa, 0x2, 0xf, 0x2, 0xf, 0x6, 0x5, 0x6, 0xe, 0x7, 0x2, 0x6, 0xf, 0x6, 0xc, 0x6, 0xc, 0x6, 0xd, 0x6, 0x5, 0x6, 0xe, 0x7, 0x4, 0x2, 0xe, 0x7, 0x3, 0x6, 0x5, 0x7, 0x2, 0x7, 0x6, 0x6, 0x5, 0x7, 0x2};
static const uint8_t LOC_W_LEN = sizeof(LOC_W) / sizeof(LOC_W[0]);

static const uint8_t SS = 2;

static const uint8_t CRED_I[] = {0xA2, 0x02, 0x77, 0x34, 0x32, 0x2D, 0x35, 0x30, 0x2D, 0x33, 0x31, 0x2D, 0x46, 0x46, 0x2D, 0x45, 0x46, 0x2D, 0x33, 0x37, 0x2D, 0x33, 0x32, 0x2D, 0x33, 0x39, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x2B, 0x20, 0x01, 0x21, 0x58, 0x20, 0xAC, 0x75, 0xE9, 0xEC, 0xE3, 0xE5, 0x0B, 0xFC, 0x8E, 0xD6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5C, 0x47, 0xBF, 0x16, 0xDF, 0x96, 0x66, 0x0A, 0x41, 0x29, 0x8C, 0xB4, 0x30, 0x7F, 0x7E, 0xB6, 0x22, 0x58, 0x20, 0x6E, 0x5D, 0xE6, 0x11, 0x38, 0x8A, 0x4B, 0x8A, 0x82, 0x11, 0x33, 0x4A, 0xC7, 0xD3, 0x7E, 0xCB, 0x52, 0xA3, 0x87, 0xD2, 0x57, 0xE6, 0xDB, 0x3C, 0x2A, 0x93, 0xDF, 0x21, 0xFF, 0x3A, 0xFF, 0xC8};
static const uint8_t CRED_R[] = {0xA2, 0x02, 0x60, 0x08, 0xA1, 0x01, 0xA5, 0x01, 0x02, 0x02, 0x41, 0x0A, 0x20, 0x01, 0x21, 0x58, 0x20, 0xBB, 0xC3, 0x49, 0x60, 0x52, 0x6E, 0xA4, 0xD3, 0x2E, 0x94, 0x0C, 0xAD, 0x2A, 0x23, 0x41, 0x48, 0xDD, 0xC2, 0x17, 0x91, 0xA1, 0x2A, 0xFB, 0xCB, 0xAC, 0x93, 0x62, 0x20, 0x46, 0xDD, 0x44, 0xF0, 0x22, 0x58, 0x20, 0x45, 0x19, 0xE2, 0x57, 0x23, 0x6B, 0x2A, 0x0C, 0xE2, 0x02, 0x3F, 0x09, 0x31, 0xF1, 0xF3, 0x86, 0xCA, 0x7A, 0xFD, 0xA6, 0x4F, 0xCD, 0xE0, 0x10, 0x8C, 0x22, 0x4C, 0x51, 0xEA, 0xBF, 0x60, 0x72};
static const BytesP256ElemLen R = {0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31, 0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03, 0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac};
static const BytesP256ElemLen I = {0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17, 0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43, 0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b};

static int has_coap_response = 0;
static uint8_t coap_payload[MAX_MESSAGE_SIZE_LEN];
static uint8_t coap_payload_len;

void print_hex(uint8_t *arr, size_t len)
{
    printf("%ld bytes: ", len);
    for (int i = 0; i < len; i++)
        printf("%02X", arr[i]);
    printf("\n");
}

static coap_response_t message_handler(coap_session_t *session COAP_UNUSED,
                                       const coap_pdu_t *sent,
                                       const coap_pdu_t *received,
                                       const coap_mid_t id COAP_UNUSED)
{
    has_coap_response = 1;
    // coap_show_pdu(COAP_LOG_WARN, received);
    const uint8_t *data;
    coap_get_data(received, &coap_payload_len, &data);
    memcpy(coap_payload, data, coap_payload_len);
    print_hex((uint8_t *)coap_payload, coap_payload_len);
    return COAP_RESPONSE_OK;
}

int main(void)
{
    printf("Calling lakers from C!\n");

    CredentialRPK cred_i = {0}, cred_r = {0};
    credential_rpk_new(CRED_I, 84, &cred_i);
    credential_rpk_new(CRED_R, 84, &cred_r);

    // coap init
    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;
    coap_address_t dst;
    coap_pdu_t *pdu = NULL;
    coap_startup();
    coap_set_log_level(COAP_LOG_WARN);
    coap_address_init(&dst);
    dst.addr.sin.sin_family = AF_INET;
    dst.addr.sin.sin_port = htons(5683);
    inet_pton(AF_INET, "127.0.0.1", &(dst.addr.sin.sin_addr));
    if (!(ctx = coap_new_context(NULL)))
    {
        coap_log_emerg("cannot create libcoap context\n");
        goto finish;
    }
    if (!(session = coap_new_client_session(ctx, NULL, &dst,
                                            COAP_PROTO_UDP)))
    {
        coap_log_emerg("cannot create client session\n");
        goto finish;
    }
    coap_register_response_handler(ctx, message_handler);

    // lakers test gen keys
    puts("Begin test: generate key pair.");
    uint8_t out_private_key[32] = {0};
    uint8_t out_public_key[32] = {0};
    p256_generate_key_pair_from_c(out_private_key, out_public_key);
    print_hex(out_private_key, 32);
    print_hex(out_public_key, 32);
    puts("End test: generate key pair.");

    // lakers init
    puts("creating edhoc initiator.");
    EdhocInitiatorC initiator = initiator_new();

#ifdef LAKERS_EAD_AUTHZ
    puts("creating ead-authz device.");
    ZeroTouchDevice device = authz_device_new(ID_U, ID_U_LEN, &G_W, LOC_W, LOC_W_LEN);
    puts("computing authz_secret.");
    BytesP256ElemLen authz_secret;
    initiator_compute_ephemeral_secret(&initiator, &G_W, &authz_secret);
    puts("computing ead_1.");
    ZeroTouchDeviceWaitEAD2 device_wait;
    EADItemC ead_1;
    authz_device_prepare_ead_1(&device, &authz_secret, SS, &device_wait, &ead_1);
    print_hex(ead_1.value->content, ead_1.value->len);
#endif

    puts("Begin test: edhoc initiator.");
    EdhocMessageBuffer message_1;
    EdhocInitiatorWaitM2C initiator_wait_m2;
#ifdef LAKERS_EAD_AUTHZ
    int res = initiator_prepare_message_1(&initiator, NULL, &ead_1, &initiator_wait_m2, &message_1);
#else
    int res = initiator_prepare_message_1(&initiator, NULL, NULL, &initiator_wait_m2, &message_1);
#endif
    if (res != 0)
        printf("Error prep msg1: %d\n", res);
    print_hex(message_1.content, message_1.len);

    // coap_send(message_1);
    pdu = coap_pdu_init(COAP_MESSAGE_CON,
                        COAP_REQUEST_CODE_GET,
                        coap_new_message_id(session),
                        coap_session_max_pdu_size(session));
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 17, (const uint8_t *)".well-known/edhoc");
    uint8_t payload[MAX_MESSAGE_SIZE_LEN];
    payload[0] = 0xf5;
    memcpy(payload + 1, message_1.content, message_1.len);
    coap_add_data(pdu, message_1.len + 1, payload);
    // coap_show_pdu(COAP_LOG_WARN, pdu);
    if (coap_send(session, pdu) == COAP_INVALID_MID)
    {
        coap_log_err("cannot send CoAP pdu\n");
        goto finish;
    }
    while (has_coap_response == 0)
        coap_io_process(ctx, COAP_IO_WAIT);
    has_coap_response = 0;

    puts("processing msg2");
    EdhocMessageBuffer message_2 = {.len = coap_payload_len};
    memcpy(message_2.content, coap_payload, coap_payload_len);
    EdhocInitiatorProcessingM2C initiator_processing_m2;
    uint8_t c_r;
    CredentialRPK fetched_cred_r = {0};
    // EADItemC ead_2;
    // res = initiator_parse_message_2(&initiator_wait_m2, &message_2, &CRED_R, 84, &initiator_processing_m2, &c_r, &fetched_cred_r, ead_2);
    res = initiator_parse_message_2(&initiator_wait_m2, &message_2, &CRED_R, 84, &initiator_processing_m2, &c_r, &fetched_cred_r, NULL);
    if (res != 0)
        printf("Error parse msg2: %d\n", res);
    EdhocInitiatorProcessedM2C initiator_processed_m2;
    initiator_verify_message_2(&initiator_processing_m2, &I, cred_i, fetched_cred_r, &initiator_processed_m2);
    if (res != 0)
        printf("Error verify msg2: %d\n", res);

    puts("processing msg3");
    EdhocInitiatorDoneC initiator_done;
    EdhocMessageBuffer message_3;
    uint8_t prk_out[SHA256_DIGEST_LEN];
    res = initiator_prepare_message_3(&initiator_processed_m2, ByReference, NULL, &initiator_done, &message_3, prk_out);
    if (res != 0)
        printf("Error verify msg2: %d\n", res);

    // coap_send(message_2);
    pdu = coap_pdu_init(COAP_MESSAGE_CON,
                        COAP_REQUEST_CODE_GET,
                        coap_new_message_id(session),
                        coap_session_max_pdu_size(session));
    coap_add_option(pdu, COAP_OPTION_URI_PATH, 17, (const uint8_t *)".well-known/edhoc");
    // uint8_t payload[MAX_MESSAGE_SIZE_LEN];
    payload[0] = c_r;
    memcpy(payload + 1, message_3.content, message_3.len);
    coap_add_data(pdu, message_3.len + 1, payload);
    // coap_show_pdu(COAP_LOG_WARN, pdu);
    if (coap_send(session, pdu) == COAP_INVALID_MID)
    {
        coap_log_err("cannot send CoAP pdu\n");
        goto finish;
    }
    while (has_coap_response == 0)
        coap_io_process(ctx, COAP_IO_WAIT);
    has_coap_response = 0;

    puts("All went good.");

finish:
    coap_session_release(session);
    coap_free_context(ctx);
    coap_cleanup();

    return 0;
}
