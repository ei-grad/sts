/* ====================================================================
 *
 * Copyright (c) 1995-1998 Eric Young (eay@cryptsoft.com)
 *
 * Copyright (c) 1998-2001 The OpenSSL Project.
 *
 * Copyright (c) 2011 Andrew Grigorev <andrew@ei-grad.ru>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 * must display the following acknowledgment:
 *
 *   This product includes software written by Andrew Grigorev
 *   <andrew@ei-grad.ru>.
 *
 *   This product includes software developed by the OpenSSL Project for use in
 *   the OpenSSL Toolkit (http://www.openssl.org/).
 *
 *   This product includes cryptographic software written by Eric Young
 *   (eay@cryptsoft.com).
 *
 *   This product includes software written by Tim Hudson (tjh@cryptsoft.com).
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 * endorse or promote products derived from this software without prior written
 * permission. For written permission, please contact openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL" nor may
 * "OpenSSL" appear in their names without prior written permission of the
 * OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 * acknowledgment:
 *
 *   This product includes software written by Andrew Grigorev
 *   <andrew@ei-grad.ru>.
 *
 *   This product includes software developed by the OpenSSL Project for use in
 *   the OpenSSL Toolkit (http://www.openssl.org/).
 *
 *   This product includes cryptographic software written by Eric Young
 *   (eay@cryptsoft.com).
 *
 *   This product includes software written by Tim Hudson (tjh@cryptsoft.com).
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE OpenSSL PROJECT OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software written by Andrew Grigorev
 * <andrew@ei-grad.ru>.
 *
 * This product includes software developed by the OpenSSL Project for use in
 * the OpenSSL Toolkit (http://www.openssl.org/).
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).
 *
 * This product includes software written by Tim Hudson (tjh@cryptsoft.com).
 *
 */

#include <string.h>

#include <openssl/ui.h>
#include <openssl/bio.h>

#include "util.h"

static UI_METHOD *ui_method = NULL;

BIO * bio_out = NULL;
BIO * bio_err = NULL;

void destroy_ui_method(void) {
	if(ui_method) {
		UI_destroy_method(ui_method);
		ui_method = NULL;
	}
}

void gen_cb(int p, int n, void *param) {

    char c=' ';

    if (p == 0) c='.';
    if (p == 1) c='+';
    if (p == 2) c='*';
    if (p == 3) c='\n';
    BIO_write(bio_err, &c, 1);
    (void)BIO_flush(bio_err);

    return;
}

int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp) {
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data) {
		if (cb_data->password)
			password = cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}

	if (password) {
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}

	ui = UI_new_method(ui_method);
	if (ui) {
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase",
			prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui,prompt,ui_flags,buf,
				PW_MIN_LENGTH,BUFSIZ-1);
		if (ok >= 0 && verify)
			{
			buff = (char *)OPENSSL_malloc(bufsiz);
			ok = UI_add_verify_string(ui,prompt,ui_flags,buff,
				PW_MIN_LENGTH,BUFSIZ-1, buf);
			}
		if (ok >= 0)
			do {
				ok = UI_process(ui);
			} while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff) {
			OPENSSL_cleanse(buff,(unsigned int)bufsiz);
			OPENSSL_free(buff);
		}

		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1) {
			BIO_printf(bio_err, "User interface error\n");
			ERR_print_errors_fp(stderr);
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		if (ok == -2) {
			printf("aborted!\n");
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		UI_free(ui);
		OPENSSL_free(prompt);
	}
	return res;
}

