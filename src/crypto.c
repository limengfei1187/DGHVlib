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

#include "dghv.h"

void DGHV_encrypt(__cit* ciphertext, unsigned long plaintext, __pubkey_set* pubkey, __sec_setting* para, randstate rs){

 	unsigned long i, r;
 	mpz_t rn;
 	mpz_init(rn);

 	for(i = 0; i < para->lam / 2; i++){
        do{
            gen_rrandomb(rn, rs, para->lam / 2);
            mpz_mod_ui(rn, rn, para->tau + 1);
     		r = mpz_get_ui(rn);
        }while(r == 0);
 		mpz_add(ciphertext->c,ciphertext->c,pubkey->pks[r]);
 	}
 	mpz_mul_ui(ciphertext->c,ciphertext->c,2);
 	mpz_mod(ciphertext->c,ciphertext->c,pubkey->pks[0]);
 	gen_rrandomb(rn,rs, para->Rho);
 	mpz_mul_ui(rn,rn,2);
 	mpz_add_ui(rn,rn,plaintext);
 	mpz_add(ciphertext->c,ciphertext->c,rn);
 	mpz_clear(rn);
 }


 unsigned long DGHV_decrypt(__cit* ciphertext, __prikey* prikey){
 	mpz_t plaintext;
 	mpz_init(plaintext);
 	mpz_mod(plaintext,ciphertext->c,prikey->sk);
 	mpz_mod_ui(plaintext,plaintext,2);
    unsigned long pl = mpz_get_ui(plaintext);
    mpz_clear(plaintext);
 	return pl;
 }
