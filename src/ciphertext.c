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

 void init_cit(__cit** ciph, size_t Theta){
     unsigned long i;
     *ciph = (__cit*)malloc(sizeof(__cit));
     (*ciph)->z = (mpf_t*)malloc(Theta * sizeof(mpf_t));
     mpz_init((*ciph)->c);
     for(i = 0; i < Theta; i++){
         mpf_init((*ciph)->z[i]);
     }
     (*ciph)->z_size = Theta;
 }

 void expend_cit(__cit* ciph, __pubkey_set* pubkey){
     unsigned long i;
     mpf_t zz;
     mpf_init(zz);
     mpf_set_z(zz, ciph->c);
     for(i = 0; i < ciph->z_size; i++){
         mpf_mul(ciph->z[i], zz, pubkey->y[i]);
     }
     mpf_clear(zz);
 }

 void clear_cit(__cit* ciph){
     unsigned long i;
     mpz_clear(ciph->c);
     for(i = 0; i < ciph->z_size; i++){
         mpf_clear(ciph->z[i]);
     }
     free(ciph->z);
     free(ciph);
 }
