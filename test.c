/* Copyright (C) 2018-2019 SAU Network Communication Research Room.
 * This program is Licensed under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */

#include <stdio.h>
#include <string.h>
#include <gmp.h>
#include "dghv.h"

typedef __prikey* privatekey;
typedef __pubkey_set* publickey;
typedef __cit*    ciphertext;
typedef __sec_setting* sec_setting;


int main(){


    sec_setting para;
    privatekey prikey;
    publickey  pubkey;
    ciphertext c1, c2, c3, new;

    init_sec_para(&para);
    set_default_para(para, TOY);
    mpf_set_default_prec(2 * para->eta + para->gam);

    init_sk(&prikey, para);
    init_pkset(&pubkey, para);
    init_cit(&c1, para->Theta);
    init_cit(&c2, para->Theta);
    init_cit(&c3, para->Theta);
    init_cit(&new, para->Theta);


    unsigned long seed = get_seed();
    randstate rs;
    set_randstate(rs, seed);
    gen_prikey(prikey, rs);
    gen_pubkey(pubkey, prikey, para, rs, 1);
    expand_p2y(pubkey, prikey, para->prec, rs);

    privatekey prikey1;
    publickey  pubkey1;
    sec_setting para1;

    init_sec_para(&para1);


    printf("save_parameters\n");
    save_sec_para(para, "parameters");
    printf("read_parameters\n");
    read_sec_para(para1, "parameters");

    init_sk(&prikey1, para1);
    init_pkset(&pubkey1, para1);

    printf("save_pubkey\n");
    save_pubkey(pubkey, "publickey.key");
    printf("read_pubkey\n");
    read_pubkey(pubkey1, "publickey.key");

    printf("save_prikey\n");
    save_prikey(prikey, "privatekey.key");
    printf("read_prikey\n");
    read_prikey(prikey1, "privatekey.key");

    unsigned long i;



    if(mpz_cmp(prikey->sk, prikey1->sk)==0) printf("prikey->sk = prikey1->sk\n");
    else printf("prikey->sk != prikey1->sk\n");


    for(i = 0; i < para->Theta; i++){
        if(mpz_cmp(prikey->sk_rsub[i], prikey1->sk_rsub[i]) == 0){
            printf("prikey->sk_rsub[%ld] = prikey1->sk_rsub[%ld]\n", i, i);
        }else{
            printf("prikey->sk_rsub[%ld] != prikey1->sk_rsub[%ld]\n",i, i);
        }
    }
    if(prikey->rsub_size == prikey1->rsub_size) printf("prikey->rsub_size = prikey1->rsub_size\n");
    else printf("prikey->rsub_size != prikey1->rsub_size\n");

    if(prikey->rsub_hw == prikey1->rsub_hw) printf("prikey->rsub_hw = prikey1->rsub_hw\n");
    else printf("prikey->rsub_hw != prikey1->rsub_hw\n");

    if(prikey->sk_bit_cnt == prikey1->sk_bit_cnt) printf("prikey->sk_bit_cnt = prikey1->sk_bit_cnt\n");
    else printf("prikey->sk_bit_cnt != prikey1->sk_bit_cnt\n");

    if(strcmp(prikey->gen_time, prikey1->gen_time)==0)printf("prikey->gen_time = prikey1->gen_time\n");


    if(mpz_cmp(pubkey->x0, pubkey1->x0) == 0) printf("x0 ok\n");

    for(i = 0; i < para->tau; i++){
        if(mpz_cmp(pubkey->pks[i], pubkey1->pks[i])==0)printf("pks[%ld] OK\n", i);
    }

    for(i = 0; i < para->Theta; i++){
        if(mpz_cmp(pubkey->cs[i], pubkey1->cs[i])==0) printf("cs[%ld] OK\n", i);
    }

    for(i = 0; i < para->Theta; i++){
        if(mpf_cmp(pubkey->y[i], pubkey1->y[i])==0) printf("y[%ld] OK\n", i);
    }

    if(pubkey->pks_size == pubkey1->pks_size) printf("pks_size OK\n");
    if(pubkey->y_size == pubkey1->y_size) printf("y_size OK\n");
    if(pubkey->pk_bit_cnt == pubkey1->pk_bit_cnt) printf("pk_bit_cnt OK\n");
    if(strcmp(pubkey->gen_time, pubkey1->gen_time)==0) printf("gen_time OK\n");

    unsigned long m1 = 1, m2 = 0, res;
    printf("m1= %lu\n", m1);
    DGHV_encrypt(c1, m1, pubkey1, para1, rs);
    expend_cit(c1, pubkey1);
    //gmp_printf("c1= %Zd\n", c1->c);



    res = DGHV_decrypt(c1, prikey1);
    printf("res= %lu\n", res);

    printf("m2= %lu\n", m2);
    DGHV_encrypt(c2, m2, pubkey1, para1, rs);
    expend_cit(c2, pubkey1);
    //gmp_printf("c2= %Zd\n", c2->c);

    res = DGHV_decrypt(c2, prikey1);
    printf("res= %lu\n", res);
    char** copy_bufmap;
    char** bufmap = (char**)malloc(2*sizeof(char*));
    printf("save_str\n");
    bufmap[0] = format_ciphertext_str(c1);
    printf("save_str\n");
    bufmap[1] = format_ciphertext_str(c2);

    printf("save_str\n");


    save_str(bufmap, 2, "CCC");
    printf("save_str\n");
    copy_bufmap = read_str("CCC");
    printf("save_str\n");

    ciphertext c4, c5;
    init_cit(&c4, para->Theta);
    init_cit(&c5, para->Theta);

    format_str_ciphertext(copy_bufmap[1],  c4);
    format_str_ciphertext(copy_bufmap[2],  c5);


    if(mpz_cmp(c1->c, c4->c)==0) printf("OK\n");
    if(mpz_cmp(c2->c, c5->c)==0) printf("OK\n");

    mpf_t sum,rp,diff;
	mpf_init_set_ui(sum,0);
	mpf_init(rp);
	mpf_init(diff);
	mpf_set_z(rp,prikey1->sk);
	mpf_ui_div(rp,1,rp);

	gmp_printf("秘钥p的倒数：%.Ff\n", rp);

	for(i=0;i<para1->Theta;i++){

		if(mpz_cmp_ui(prikey1->sk_rsub[i], 1) == 0){
			mpf_add(sum,sum,pubkey1->y[i]);
		}
	}

	gmp_printf("y[i]的和：%.Ff\n",sum);

	mpf_sub(diff,rp,sum);
	gmp_printf("误差：%.Ff\n",diff);

    mpf_t fc2;
    mpf_init(fc2);
    mpf_set_z(fc2, c2->c);
    mpf_set_z(rp,prikey1->sk);
	mpf_div(rp,fc2,rp);
    mpf_set_ui(sum, 0);

    for(i=0;i<para1->Theta;i++){

		if(mpz_cmp_ui(prikey1->sk_rsub[i], 1) == 0){
			mpf_add(sum,sum,c2->z[i]);
            //gmp_printf("%Zd\n",prikey->sk_rsub[i]);
		}
	}

    mpf_sub(diff,rp,sum);
	gmp_printf("误差：%.Ff\n",diff);



    unsigned long lsb1, lsb2;
    lsb1 = get_ciph_lsb(c2);
    printf("lsb1=%lu\n", lsb1);
    lsb2 = get_ciphdivp_lsb(c2, prikey1, para1);

    printf("lsb2=%lu\n", lsb2);
    printf("new_plaintext = (lsb1 + lsb2) mod 2 = %lu\n", (lsb1 + lsb2) % 2 );
    if((lsb1 + lsb2) % 2 == res) printf("压缩解密电路测试成功\n");
    else printf("压缩解密电路测试失败\n");

    evaluate_mul(c3, c1, c2, pubkey1->pks[0]);
    expend_cit(c3, pubkey1);

    bootstrap(new, c3, pubkey1, para1, rs);


    res = DGHV_decrypt(new, prikey1);

    if(res == 0) printf("密文刷新成功\n");
    else printf("密文刷新失败\n");

    free(para);
    clear_sk(prikey);
    clear_pkset(pubkey);

    free(para1);
    clear_sk(prikey1);
    clear_pkset(pubkey1);
    clear_cit(c1);
    clear_cit(c2);
    clear_cit(c3);
    return 0;

}
