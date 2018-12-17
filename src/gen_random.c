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


unsigned long get_seed(){
    struct timeval t_val;
	gettimeofday(&t_val, NULL);
	unsigned long seed = t_val.tv_sec*1000*1000 + t_val.tv_usec;
    return seed;
}

void set_randstate(randstate rs, unsigned long seed){
	gmp_randinit_default(rs);
	gmp_randseed_ui(rs,seed);
}

void gen_rrandomb(mpz_t rn, randstate rs, unsigned long n){
	mpz_rrandomb(rn,rs,n);
}

void gen_urandomm(mpz_t rn, randstate rs, mpz_t ub){
	mpz_urandomm(rn,rs,ub);
}
