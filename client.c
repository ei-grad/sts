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

#include <string.h>
#include <openssl/ssl.h>
#include "common.h"


int STS_ClientAct1(STS *sts) {

    printf("\n==== Этап 1 ====\n");

    if(STS_GenDHKeys(sts)) return 1;
    if(STS_SendDHPubKey(sts)) return 1;

    return 0;
}

int STS_ClientAct2(STS *sts) {

    printf("\n==== Этап 2 ====\n");

    if(STS_RecvDHPubKey(sts)) return 1;
    if(STS_CalcDHSharedKey(sts)) return 1;
    if(STS_SyncSend(sts)) return 1;
    if(STS_RecvExponents(sts)) return 1;

    return 0;
}

int STS_ClientAct3(STS * sts) {

    printf("\n==== Этап 3 ====\n");

    STS_SendExponents(sts);

    return 0;
}

int STS_ClientConnect(STS * sts, char * addr) {

    sts->conn = BIO_new_connect(addr);

    if(BIO_do_connect(sts->conn) <= 0) {
        fprintf(stderr, "Не удалось подключиться к серверу!\n");
        return 1;
    }

    return 0;
}

int STS_ClientMain(char ** argv) {

	int ret = 1;
    STS sts;
    memset(&sts, 0, sizeof(sts));

    if(STS_ClientConnect(&sts, argv[0]))
        goto STS_ClientMain_err;

    if(STS_ReadKeys(&sts, argv[1], argv[2], argv[3]))
        goto STS_ClientMain_err;

    if(STS_ClientAct1(&sts)) {
        printf("Ошибка при прохождении первого этапа!\n");
        goto STS_ClientMain_err;
    }

    if(STS_ClientAct2(&sts)) {
        printf("Ошибка при прохождении второго этапа!\n");
        goto STS_ClientMain_err;
    }

    if(STS_ClientAct3(&sts)) {
        printf("Ошибка при прохождении третьего этапа!\n");
        goto STS_ClientMain_err;
    }

	ret = 0;

STS_ClientMain_err:
    STS_Free(&sts);

    return 0;
}

