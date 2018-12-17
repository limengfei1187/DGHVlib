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

 void init_sk(__prikey** prikey, __sec_setting* para){
     int i;
     *prikey = (__prikey*)malloc(sizeof(__prikey));
     (*prikey)->sk_rsub = (mpz_t*)malloc(para->Theta * sizeof(mpz_t));

     mpz_init((*prikey)->sk);
     for(i = 0; i < para->Theta; i++){
         mpz_init_set_ui((*prikey)->sk_rsub[i], 0);
     }
     (*prikey)->rsub_size = para->Theta;
     (*prikey)->rsub_hw = para->theta;
     (*prikey)->sk_bit_cnt = para->eta;
 }

 void init_pkset(__pubkey_set** pubkey, __sec_setting* para){
     int i;
     *pubkey = (__pubkey_set*)malloc(sizeof(__pubkey_set));
     (*pubkey)->pks = (mpz_t*)malloc(para->tau * sizeof(mpz_t));
     (*pubkey)->cs = (mpz_t*)malloc(para->Theta * sizeof(mpz_t));
     (*pubkey)->y = (mpf_t*)malloc(para->Theta * sizeof(mpf_t));
     mpz_init((*pubkey)->x0);

     for(i = 0; i < para->Theta; i++){
         mpz_init_set_ui((*pubkey)->cs[i], 0);
         mpf_init((*pubkey)->y[i]);
     }
     for(i = 0; i < para->tau; i++){
         mpz_init((*pubkey)->pks[i]);
     }
     (*pubkey)->pks_size = para->tau;
     (*pubkey)->y_size = para->Theta;
     (*pubkey)->pk_bit_cnt = para->gam;
 }



 void clear_sk(__prikey* prikey){
     int i;
     for(i = 0; i < prikey->rsub_size; i++){
         mpz_clear(prikey->sk_rsub[i]);
     }
     //prikey->rsub_size = 0;
     mpz_clear(prikey->sk);
     free(prikey->sk_rsub);
     free(prikey);
 }

 void clear_pkset(__pubkey_set* pubkey){
     int i;
     for(i = 0; i < pubkey->pks_size; i++){
         mpz_clear(pubkey->pks[i]);
     }
     for(i = 0; i < pubkey->y_size; i++){
         mpf_clear(pubkey->y[i]);
         mpz_clear(pubkey->cs[i]);
     }
     mpz_clear(pubkey->x0);
     //pubkey->pks_size = 0;
     //pubkey->z_size = 0;
     free(pubkey->cs);
     free(pubkey->pks);
     free(pubkey->y);
     free(pubkey);

 }
