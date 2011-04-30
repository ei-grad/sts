/*

  Copyright (c) 2011, Андрей Григорьев <andrew@ei-grad.ru>

  Данная лицензия разрешает лицам, получившим копию данного программного
  обеспечения и сопутствующей документации (в дальнейшем именуемыми
  «Программное Обеспечение»), безвозмездно использовать Программное Обеспечение
  без ограничений, включая неограниченное право на использование, копирование,
  изменение, добавление, публикацию, распространение, сублицензирование и/или
  продажу копий Программного Обеспечения, также как и лицам, которым
  предоставляется данное Программное Обеспечение, при соблюдении следующих
  условий:

  Указанное выше уведомление об авторском праве и данные условия должны быть
  включены во все копии или значимые части данного Программного Обеспечения.

  ДАННОЕ ПРОГРАММНОЕ ОБЕСПЕЧЕНИЕ ПРЕДОСТАВЛЯЕТСЯ «КАК ЕСТЬ», БЕЗ КАКИХ-ЛИБО
  ГАРАНТИЙ, ЯВНО ВЫРАЖЕННЫХ ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ ОГРАНИЧИВАЯСЬ
  ГАРАНТИЯМИ ТОВАРНОЙ ПРИГОДНОСТИ, СООТВЕТСТВИЯ ПО ЕГО КОНКРЕТНОМУ НАЗНАЧЕНИЮ И
  ОТСУТСТВИЯ НАРУШЕНИЙ ПРАВ. НИ В КАКОМ СЛУЧАЕ АВТОРЫ ИЛИ ПРАВООБЛАДАТЕЛИ НЕ
  НЕСУТ ОТВЕТСТВЕННОСТИ ПО ИСКАМ О ВОЗМЕЩЕНИИ УЩЕРБА, УБЫТКОВ ИЛИ ДРУГИХ
  ТРЕБОВАНИЙ ПО ДЕЙСТВУЮЩИМ КОНТРАКТАМ, ДЕЛИКТАМ ИЛИ ИНОМУ, ВОЗНИКШИМ ИЗ,
  ИМЕЮЩИМ ПРИЧИНОЙ ИЛИ СВЯЗАННЫМ С ПРОГРАММНЫМ ОБЕСПЕЧЕНИЕМ ИЛИ ИСПОЛЬЗОВАНИЕМ
  ПРОГРАММНОГО ОБЕСПЕЧЕНИЯ ИЛИ ИНЫМИ ДЕЙСТВИЯМИ С ПРОГРАММНЫМ ОБЕСПЕЧЕНИЕМ.

*/

#include <openssl/ssl.h>
#include "common.h"
#include "util.h"

#define BUFSIZE 1024
char buf[BUFSIZE];


int STS_ReadKeys(STS *sts, char *rsa_fname, char *partner_rsa_fname,
        char *dh_fname) {

    int ret = 1;
    char * tmpstr;
    BIO *rsa_bio = NULL;
    BIO *partner_rsa_bio = NULL;
    BIO *dh_bio = NULL;

    rsa_bio = BIO_new_file(rsa_fname, "r");
    if(!rsa_bio) goto STS_ReadKeys_err;

    sts->rsa = PEM_read_bio_RSAPrivateKey(rsa_bio, NULL,
            (pem_password_cb*)password_callback, NULL);
    if(!sts->rsa) goto STS_ReadKeys_err;

    printf("Считан секретный ключ RSA.\n");

    tmpstr = BN_bn2dec(sts->rsa->n);
    printf("Модуль: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(sts->rsa->e);
    printf("Публичная экспонента: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(sts->rsa->d);
    printf("Секретная экспонента: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    if(sts->rsa->p){
        tmpstr = BN_bn2dec(sts->rsa->p);
        printf("p = %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    }

    if(sts->rsa->q){
        tmpstr = BN_bn2dec(sts->rsa->q);
        printf("q = %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    }

    printf("\n");

    partner_rsa_bio = BIO_new_file(partner_rsa_fname, "r");
    if(!partner_rsa_bio) goto STS_ReadKeys_err;

    sts->partner_rsa = PEM_read_bio_RSA_PUBKEY(partner_rsa_bio, NULL,
            (pem_password_cb*)password_callback, NULL);
    if(!sts->partner_rsa) goto STS_ReadKeys_err;

    printf("Считан публичный RSA ключ партнера.\n");

    tmpstr = BN_bn2dec(sts->partner_rsa->n);
    printf("Модуль: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(sts->partner_rsa->e);
    printf("Публичная экспонента: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    if(sts->partner_rsa->p){
        tmpstr = BN_bn2dec(sts->partner_rsa->p);
        printf("p = %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    }

    if(sts->partner_rsa->q){
        tmpstr = BN_bn2dec(sts->partner_rsa->q);
        printf("q = %s\n", tmpstr);
        OPENSSL_free(tmpstr);
    }

    printf("\n");

    dh_bio = BIO_new_file(dh_fname, "r");
    if(!dh_bio) goto STS_ReadKeys_err;

    sts->dh = PEM_read_bio_DHparams(dh_bio, NULL,
            (pem_password_cb*)password_callback, NULL);
    if(!sts->dh) goto STS_ReadKeys_err;

    printf("Считаны параметры Diffie-Hellman'а\n");

    tmpstr = BN_bn2dec(sts->dh->p);
    printf("p = %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(sts->dh->g);
    printf("a = %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    printf("\n");

    ret = 0;
STS_ReadKeys_err:

    if(rsa_bio) BIO_free_all(rsa_bio);
    if(partner_rsa_bio) BIO_free_all(partner_rsa_bio);
    if(dh_bio) BIO_free_all(dh_bio);

    return ret;
}

int STS_GenDHKeys(STS *sts) {

    char *tmpstr;

    printf("Генерируем ключи DH.\n");

    if(!DH_generate_key(sts->dh)) {
        printf("Не удалось сгенерировать ключ.\n");
        return 1;
    }

    tmpstr = BN_bn2dec(sts->dh->priv_key);
    printf("Секретный ключ: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(sts->dh->pub_key);
    printf("Публичный ключ: %s\n", tmpstr);
    OPENSSL_free(tmpstr);

    return 0;
}

int STS_CalcDHSharedKey(STS *sts) {

    char *tmpstr;
    BIGNUM *K_bn;

    printf("Вычисляем общий ключ K.\n");

    // выделяем память под буфер для вычисления общего ключа
    sts->K = (char*) malloc((size_t)DH_size(sts->dh));

    // вычисляем общий ключ K = a^xy mod p
    sts->K_len = DH_compute_key(sts->K, sts->partner_dh_pub, sts->dh);
    if(sts->K_len == -1) {
        printf("Ошибка при вычислении общего ключа!\n");
        return 1;
    }

    K_bn = BN_new();
    BN_bin2bn(sts->K, sts->K_len, K_bn);
    tmpstr = BN_bn2dec(K_bn);
    printf("Общий ключ: %s\n\n", tmpstr);
    OPENSSL_free(tmpstr);
    BN_free(K_bn);

    return 0;
}

int STS_SendDHPubKey(STS *sts) {

    int bytes = 0;
    char *tmpstr;

    printf("Отправляем партнеру публичный ключ.\n\n");

    tmpstr = BN_bn2dec(sts->dh->pub_key);
    if(BIO_puts(sts->conn, tmpstr) <= 0) {
        printf("Ошибка связи при отправке публичного ключа.\n");
        return 1;
    }
    OPENSSL_free(tmpstr);

    return 0;
}

int STS_RecvDHPubKey(STS *sts) {

    int bytes;

    printf("Получаем публичный ключ партнера.\n");

    bytes = BIO_read(sts->conn, buf, BUFSIZE);
    if(bytes <= 0) {
        printf("Ошибка связи при получении публичного DH ключа партнера!\n");
        return 1;
    }
    buf[bytes] = 0;
    if(!BN_dec2bn(&sts->partner_dh_pub, buf)) {
        printf("Ошибка при получении публичного DH ключа партнера!\n");
        return 1;
    }

    printf("Принят публичный ключ клиента: %s\n\n", buf);

    return 0;
}

int STS_SyncSend(STS *sts) {
	if(BIO_puts(sts->conn, "SYNC") <= 0) {
		printf("Ошибка связи при синхронизации!\n");
		return 1;
	}
	return 0;
}

int STS_SyncRecv(STS *sts) {

    int bytes = BIO_read(sts->conn, buf, BUFSIZE);

    if(bytes <= 0) {
        printf("Ошибка связи при синхронизации!\n");
        return 1;
    }    buf[bytes] = 0;

    if(strcmp(buf, "SYNC")) {
        printf("Ошибка при синхронизации.\n");
        return 1;
    }

    return 0;
}

int STS_CalcDigest(BIGNUM *a, BIGNUM *b, unsigned char *md_value, int *md_len) {

    EVP_MD_CTX mdctx;
    char *tmpstr;

    printf("Вычисляем для подписи контрольную сумму ключей.\n");

    EVP_MD_CTX_init(&mdctx);
    EVP_DigestInit_ex(&mdctx, EVP_md5(), NULL);

    tmpstr = BN_bn2dec(a);
    if(!EVP_DigestUpdate(&mdctx, tmpstr, strlen(tmpstr))) {
		printf("Ошибка при вычислении контрольной суммы для подписи!\n");
		OPENSSL_free(tmpstr);
		return 1;
	}
    OPENSSL_free(tmpstr);

    tmpstr = BN_bn2dec(b);
    if(!EVP_DigestUpdate(&mdctx, tmpstr, strlen(tmpstr))) {
		printf("Ошибка при вычислении контрольной суммы для подписи!\n");
		OPENSSL_free(tmpstr);
		return 1;
	}
    OPENSSL_free(tmpstr);

    if(!EVP_DigestFinal(&mdctx, md_value, md_len)) {
        printf("Ошибка при вычислении контрольной суммы для подписи!\n");
        return 1;
    }
    return 0;
}

int STS_Sign(STS *sts, unsigned char *md_value, int md_len,
        unsigned char *buf, int *bytes) {
    if(!RSA_sign(NID_md5, md_value, md_len, buf, bytes, sts->rsa)) {
        printf("Ошибка при подписи.\n");
        return 1;
    }
    return 0;
}

int STS_Verify(STS *sts, unsigned char *md_value, int md_len,
        unsigned char *buf, int bytes) {
    if(!RSA_verify(NID_md5, md_value, md_len, buf, bytes, sts->partner_rsa)) {
        printf("Подпись не верна!\n");
        return 1;
    }
    printf("Подпись верна!\n");
    return 0;
}

int STS_Cipher(STS *sts, char *buf, int *bytes, int do_encrypt) {

    int ret = 1;
    char *tmpbuf = NULL;
    int i;
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER *cipher = NULL;
    char *iv;

    if(*bytes + EVP_MAX_BLOCK_LENGTH > BUFSIZE) {
        printf("Буффер слишком мал!\n");
        return 1;
    }

    if(sts->K_len >= 32)
        cipher = EVP_aes_256_cbc();
    else if(sts->K_len >= 24)
        cipher = EVP_aes_192_cbc();
    else if(sts->K_len >= 16)
        cipher = EVP_aes_128_cbc();

    if(!cipher) {
        printf("Неудалось выбрать алгоритм шифрования, попробуйте увеличить длину параметров DH.\n");
        return 1;
    }

    tmpbuf = (char*) malloc((size_t)*bytes);
    memcpy(tmpbuf, buf, *bytes);

    iv = (char*)malloc(EVP_CIPHER_iv_length(cipher));
    for(i=0;i<EVP_CIPHER_iv_length(cipher);i++)
        iv[i] = i;

    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, cipher, NULL, sts->K, iv, do_encrypt);

    i = *bytes;

    if(!EVP_CipherUpdate(&ctx, buf, bytes, tmpbuf, i))
        goto STS_Encrpyt_err;

    if(!EVP_CipherFinal_ex(&ctx, buf+*bytes, &i))
        goto STS_Encrpyt_err;

    *bytes += i;

    printf("Сгенерирован шифртекст длиной %d.\n", *bytes);

    ret = 0;

STS_Encrpyt_err:
    EVP_CIPHER_CTX_cleanup(&ctx);
    free(tmpbuf);
    return ret;
}

int STS_RecvExponents(STS *sts) {

    int bytes;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;

    if(STS_CalcDigest(sts->partner_dh_pub, sts->dh->pub_key,
		md_value, &md_len)) return 1;

    printf("Получаем зашифрованые подписаные публичные ключи DH.\n");

    bytes = BIO_read(sts->conn, buf, BUFSIZE);
    if(bytes <= 0) return 1;

    if(STS_Cipher(sts, buf, &bytes, 0)) return 1;

    if(STS_Verify(sts, md_value, md_len, buf, bytes))
        return 1;

    return 0;
}

int STS_SendExponents(STS *sts) {

    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;
    int bytes;

    printf("Формируем подпись публичных ключей DH.\n");

    if(STS_CalcDigest(sts->dh->pub_key, sts->partner_dh_pub,
        md_value, &md_len)) return 1;

    if(STS_Sign(sts, md_value, md_len, buf, &bytes)) return 1;

    printf("Сгенерирована подпись длиной %d байт.\n", bytes);

    printf("Шифруем подпись.\n");

    STS_Cipher(sts, buf, &bytes, 1);

    printf("Отправляем подпись партнеру.\n");

    if(BIO_write(sts->conn, buf, bytes) <= 0) return 1;

    printf("Отправлено.\n");

    return 0;
}

int STS_Free(STS *sts) {

    if(sts->conn) BIO_free(sts->conn);
    if(sts->rsa) RSA_free(sts->rsa);
    if(sts->partner_rsa) RSA_free(sts->partner_rsa);
    if(sts->dh) DH_free(sts->dh);

    if(sts->partner_dh_pub) BN_free(sts->partner_dh_pub);
    if(sts->K) free(sts->K);

    memset(sts, 0, sizeof(*sts));

    return 0;
}
