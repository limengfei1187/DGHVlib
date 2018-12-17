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

 void c_get_hw(int i, __ev_table* ev_table, __sec_setting* para, mpz_t x0){

     __hw_table* hw_table;
     int j, c, d, l, k, t, n;

     l = (int)(para->Theta + para->n - i);
     c = (int)floor(log2(para->theta + para->n - i));
     d = (i - c > 0) ? 0 : i - c;
     n = (int)pow(2, c+d);

     init_hw_table(&hw_table, (size_t)(n + 1), (size_t)(l + 1));

     for(j = 1, t = 0; j <= n; j++){
         for(k = j; k <= l; k++){
             mpz_mul(hw_table->table[j][k], ev_table->table[k - 1][i], hw_table->table[j - 1][k - 1]);
             mpz_add(hw_table->table[j][k], hw_table->table[j][k], hw_table->table[j][k - 1]);
             mpz_mod(hw_table->table[j][k], hw_table->table[j][k], x0);
         }
         if(j == (int)pow(2, t)){
             mpz_set(ev_table->table[l][i - t], hw_table->table[j][l]);
             t++;
         }
     }
     clear_hw_table(hw_table);
 }

 void c_get_ciph_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs){
     unsigned long m;
     m = get_ciph_lsb(ciph);
     DGHV_encrypt(cc, m, pubkey, para, rs);
 }

 void c_get_ciphdivp_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para){

     unsigned long i, j;
     mpz_t res;
     __ev_table* ev_table;

     mpz_init_set_ui(res, 0);
     init_ev_table(&ev_table, para->Theta + para->n, para->n + 1);

     for(i = 0; i < ciph->z_size; i++){
         set_ev_table(i, ciph->z[i], ev_table);
         for(j = 0; j < ev_table->y; j++){
             mpz_mul(ev_table->table[i][j], ev_table->table[i][j], pubkey->cs[i]);
         }
     }

     for(i = ev_table->y - 1; i > 0; i--){
         c_get_hw(i, ev_table, para, pubkey->pks[0]);
     }

     for(i = 0; i < para->Theta + para->n; i++){
         mpz_add(res, res, ev_table->table[i][0]);
     }
     mpz_add(res, res,  ev_table->table[i - 1][1]);
     mpz_mod(cc->c, res, pubkey->pks[0]);

     mpz_clear(res);
     clear_ev_table(ev_table);
 }

 void bootstrap(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs){
     __cit* c1;
     __cit* c2;
     init_cit(&c1, para->Theta);
     init_cit(&c2, para->Theta);
     c_get_ciph_lsb(c1, ciph, pubkey, para, rs);
     c_get_ciphdivp_lsb(c2, ciph, pubkey, para);
     evaluate_add(cc, c1, c2, pubkey->pks[0]);
     clear_cit(c1);
     clear_cit(c2);
 }
