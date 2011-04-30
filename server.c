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


int STS_ServerAct1(STS *sts) {

    printf("\n==== Этап 1 ====\n");

    if(STS_RecvDHPubKey(sts)) return 1;

    return 0;
}

int STS_ServerAct2(STS * sts) {

    printf("\n==== Этап 2 ====\n");

    if(STS_GenDHKeys(sts)) return 1;
    if(STS_SendDHPubKey(sts)) return 1;
    if(STS_CalcDHSharedKey(sts)) return 1;
    if(STS_SyncRecv(sts)) return 1;
    if(STS_SendExponents(sts)) return 1;

    return 0;
}

int STS_ServerAct3(STS * sts) {

    printf("\n==== Этап 3 ====\n");

	if(STS_RecvExponents(sts)) return 1;

    return 0;
}

int STS_ServerHandleConnection(BIO *conn, char **argv){

	int ret = 1;
    STS sts;
    memset(&sts, 0, sizeof(sts));

    sts.conn = conn;

    if(STS_ReadKeys(&sts, argv[0], argv[1], argv[2]))
		goto STS_ServerHandleConnection_err;

    if(STS_ServerAct1(&sts)) {
        printf("Ошибка при прохождении первого этапа!\n");
        goto STS_ServerHandleConnection_err;
    }

    if(STS_ServerAct2(&sts)) {
        printf("Ошибка при прохождении второго этапа!\n");
        goto STS_ServerHandleConnection_err;
    }

    if(STS_ServerAct3(&sts)) {
        printf("Ошибка при прохождении третьего этапа!\n");
        goto STS_ServerHandleConnection_err;
    }

	ret = 0;

STS_ServerHandleConnection_err:
    STS_Free(&sts);

    return ret;
}

int STS_ServerMain(char **argv) {

    BIO *bio_listen = BIO_new_accept(argv[0]);
    argv++;
    BIO_set_bind_mode(bio_listen, BIO_BIND_REUSEADDR);

    /* First call to BIO_accept() sets up accept BIO */
    if(BIO_do_accept(bio_listen) <= 0) {
        printf("Ошибка при создании сокета\n");
        return 1;
    }

    printf("Ждем подключения клиента.\n");

    /* Wait for incoming connection */
    if(BIO_do_accept(bio_listen) <= 0) {
        printf("Ошибка подключения!\n");
        return 1;
    }
    printf("Соединение установлено.\n");

    return STS_ServerHandleConnection(BIO_pop(bio_listen), argv);
}

