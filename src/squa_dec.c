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


 void init_hw_table(__hw_table** hwtable, size_t x, size_t y){
     int i, j;
     *hwtable = (__hw_table*)malloc(sizeof(__hw_table));
     (*hwtable)->table = (mpz_t**)malloc(x * sizeof(mpz_t*));

     for(i = 0; i < x; i++){
         (*hwtable)->table[i] = (mpz_t*)malloc(y * sizeof(mpz_t));
         for(j = 0; j < y; j++){
             if(i == 0) mpz_init_set_ui((*hwtable)->table[i][j], 1);
             else mpz_init_set_ui((*hwtable)->table[i][j], 0);

         }
     }
     (*hwtable)->x = x;
     (*hwtable)->y = y;
 }

 void init_ev_table(__ev_table** evtable, size_t x, size_t y){
     int i, j;

     *evtable = (__ev_table*)malloc(sizeof(__ev_table));
     (*evtable)->table = (mpz_t**)malloc(x * sizeof(mpz_t*));
     for(i = 0; i < x; i++){
         (*evtable)->table[i] = (mpz_t*)malloc(y * sizeof(mpz_t));
         for(j = 0; j < y; j++){
             mpz_init_set_ui((*evtable)->table[i][j], 0);
         }
     }
     (*evtable)->x = x;
     (*evtable)->y = y;
 }

 void clear_hw_table(__hw_table* hwtable){
     int i, j;
     for(i = 1; i < hwtable->x; i++){
         for(j = 1; j < hwtable->y; j++){
             mpz_clear(hwtable->table[i][j]);
         }
         free(hwtable->table[i]);
     }
     //hwtable->x = 0;
     //hwtable->y = 0;
     free(hwtable->table);
     free(hwtable);
 }

 void clear_ev_table(__ev_table* evtable){
     int i, j;
     for(i = 0; i < evtable->x; i++){
         for(j = 0; j < evtable->y; j++){
             mpz_clear(evtable->table[i][j]);
         }
         free(evtable->table[i]);
     }
     //evtable->x = 0;
     //evtable->y = 0;
     free(evtable->table);
     free(evtable);
 }

 void set_ev_table(unsigned long i, mpf_t z, __ev_table* ev_table){
     unsigned long j, val, lsb;

     if(MP_EXP(z) < 0){
         j = 0;
         while(j < ev_table->y){
             mpz_set_ui(ev_table->table[i][j++], 0);
         }
         return;
     }

     if(MP_EXP(z) > 0){
         j = MP_SIZE(z) - MP_EXP(z);
         val = LIMB(z, j);
         lsb = LSB(val);
         mpz_set_ui(ev_table->table[i][0], lsb);
         val = LIMB(z, (j - 1));
     }

     if(MP_EXP(z) == 0){
         mpz_set_ui(ev_table->table[i][0], 0);
         val = LIMB(z, (MP_SIZE(z) - 1));
     }

     val = R_N_SHIFT(val, (2 * W - (ev_table->y - 1)));
     j = ev_table->y - 1;
     while(j > 0){
         lsb = LSB(val);
         mpz_set_ui(ev_table->table[i][j--], lsb);
         val = R_N_SHIFT(val, 1);
     }
 }

 void get_hw(int i, __ev_table* ev_table, __sec_setting* para){

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
         }
         if(j == (int)pow(2, t)){
             mpz_set(ev_table->table[l][i - t], hw_table->table[j][l]);
             t++;
         }
     }
     clear_hw_table(hw_table);
 }

 unsigned long get_ciph_lsb( __cit* ciph){
     unsigned long val;
     val = LIMB(ciph->c, 0);
     val = LSB(val);
     return val;
 }

 unsigned long get_ciphdivp_lsb(__cit* ciph, __prikey* prikey, __sec_setting* para){

     unsigned long i, lsb;
     mpz_t res;
     __ev_table* ev_table;

     mpz_init_set_ui(res, 0);
     init_ev_table(&ev_table, para->Theta + para->n, para->n + 1);

     for(i = 0; i < ciph->z_size; i++){
         if(mpz_cmp_ui(prikey->sk_rsub[i], 1) == 0){
             set_ev_table(i, ciph->z[i], ev_table);
         }
     }

     for(i = ev_table->y - 1; i > 0; i--){
         get_hw(i, ev_table, para);
     }

     for(i = 0; i < para->Theta + para->n; i++){
         mpz_add(res, res, ev_table->table[i][0]);
     }
     mpz_add(res, res,  ev_table->table[i - 1][1]);
     mpz_mod_ui(res, res, 2);
     lsb = mpz_get_ui(res);

     mpz_clear(res);
     clear_ev_table(ev_table);

     return lsb;
 }
