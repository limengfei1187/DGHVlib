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

 void gen_prime(mpz_t p, size_t n, randstate rs){
     int res = -1;
 	 mpz_t rn;
 	 mpz_init(rn);
     gen_rrandomb(rn, rs, n);
     do{
 		mpz_nextprime(p,rn);
 		res = mpz_probab_prime_p (p , PROB_EXP);
 		if(res == 1) break;
 	}while(1);
     mpz_clear(rn);
 }

 void mpf_round_mpz(mpz_t rop, mpf_t op){
    unsigned long val = LIMB(op, (MP_SIZE(op)-MP_EXP(op)-1));
    if(MSB(val) == _MSBMASK){
        mpf_add_ui(op,op,1);
    }

    int i,j=0;
    char* mpzstr = (char*)malloc((MP_EXP(op)+1)*16 * sizeof(char));
    mpzstr[0] = '0'; mpzstr[1] = '\0';
    for(i = MP_SIZE(op)-1; i >= MP_SIZE(op)-MP_EXP(op); i--){
        j = sprintf(mpzstr + j, "%lx", LIMB(op,i));
    }
    mpz_init_set_str(rop, mpzstr, 16);
    free(mpzstr);
 }

 void div_round_q(mpz_t q, mpz_t  n, mpz_t d){

 	mpf_t fq, fn, fd;
    mpf_init(fq);
 	mpf_init(fn);
 	mpf_init(fd);
    mpf_set_z(fn, n);
    mpf_set_z(fd, d);

    mpf_div(fq, fn, fd);
 	mpf_round_mpz(q, fq);

 	mpf_clear(fn);
 	mpf_clear(fd);
    mpf_clear(fq);
 }

 bool is_a_rough(mpz_t a, mpz_t b){
     mpz_t c;
     mpz_init(c);
     mpz_gcd(c, a, b);
     if(mpz_cmp_ui(c, 1) == 0){
         return true;
     }
     mpz_clear(c);
     return false;
 }

 void getQs(mpz_t* q, mpz_t p, size_t gam, size_t tau, size_t lam, randstate rs){

     int i;
     mpz_t ub, lr; //ub 随机数； lr lam-rough 安全系数结果

     mpz_init(ub);
     mpz_init(lr);

     mpz_ui_pow_ui(ub,BASE,gam);
     mpz_fdiv_q(ub,ub,p);
     mpz_ui_pow_ui(lr, BASE, lam);

     mpz_init(q[0]);
     do{
         gen_urandomm(q[0], rs, ub);
     }while(mpz_odd_p(q[0]) == 0 && !is_a_rough(q[0], lr));

     //mpz_set(ub, q[0]);
     mpz_fdiv_q_ui(ub,q[0],2);
     for(i = 1; i < tau; i++){
         mpz_init(q[i]);
         do{
         	gen_urandomm(q[i], rs, ub);
        }while(!is_a_rough(q[0], lr));
         gen_urandomm(q[i], rs, ub);
     }
     mpz_clear(ub);
     mpz_clear(lr);

 }

 void randomize_ss(mpz_t* ss, size_t ss_hw, size_t ss_size){
     unsigned long  seed = get_seed();
     srand(seed);
     unsigned long i, r;
     for(i=0; i < ss_hw; i++){
 	     r= rand() % ss_size;
 	     if(mpz_cmp_ui(ss[r], 0) == 0){
             mpz_set_ui(ss[r], 1);
 	     }else if(mpz_cmp_ui(ss[r], 1) == 0){
             i=i-1;
 	     }
 	 }
 }

 void randomize_sk(mpz_t* yy, mpz_t p, size_t ss_hw, size_t prec){
     int i, j;
     mpz_t q, r,res, xp;

     mpz_init(q);
     mpz_init(r);
 	 mpz_init(res);
 	 mpz_init(xp);

     mpz_ui_pow_ui(xp, 2, prec);
 	 div_round_q(xp, xp, p);
 	 mpz_fdiv_qr_ui(q, r, xp, ss_hw);
     for(i=0; i<ss_hw; i++){
         mpz_init_set_ui(yy[i], 0);
 		 mpz_add(yy[i], yy[i], q);
 	}
    mpz_add(yy[i-1], yy[i-1], r);

     for(i=0; i<ss_hw; i++){
 		mpz_fdiv_qr_ui(q, r, yy[i], rand()%ss_hw+1);
 		mpz_add(res, q, r);
 		mpz_sub(yy[i], yy[i], res);

 		mpz_fdiv_qr_ui(q, r, res, ss_hw);
 		mpz_add(res,r,q);

 		for(j=0; j<ss_hw; j++){
 			if(j==i){
 				mpz_add(yy[j], yy[j], res);

 			}else{
 				mpz_add(yy[j], yy[j], q);
 			}
 		}
 	}

    mpz_clear(q);
 	mpz_clear(r);
 	mpz_clear(res);
 	mpz_clear(xp);
 }


 void expand_p2y(__pubkey_set* pubkey, __prikey* prikey, size_t prec, randstate rs){
     int i, j;
     mpz_t* yy;
     mpz_t rn,ui;
 	 mpf_t nu,de, bb;  //de 分母 nu 分子

     mpz_init(rn);
     mpz_init(ui);
     mpf_init(nu);
 	 mpf_init(de);
     mpf_init_set_ui(bb, BASE);
     yy = (mpz_t*)malloc(prikey->rsub_hw * sizeof(mpz_t));
     randomize_sk(yy, prikey->sk, prikey->rsub_hw, prec);

     mpz_ui_pow_ui(ui,BASE,prec+1);
 	 mpf_pow_ui(de,bb,prec);

     for(i=0, j=0; i<pubkey->y_size; i++){
 		if(mpz_cmp_ui(prikey->sk_rsub[i], 0) == 0){
 			gen_urandomm(rn, rs, ui);
 			mpf_set_z(nu,rn);
 		}else if(mpz_cmp_ui(prikey->sk_rsub[i], 1) == 0){
 			mpf_set_z(nu,yy[j]);
 			j++;
 		}
 		mpf_div(pubkey->y[i],nu,de);
 	 }

     for(i = 0; i < prikey->rsub_hw; i++) mpz_clear(yy[i]);
     free(yy);
     mpz_clear(rn);
 	 mpz_clear(ui);
     mpf_clear(nu);
 	 mpf_clear(de);
     mpf_clear(bb);
 }

 void encrypt_sk(__pubkey_set* pubkey, __prikey* prikey, randstate rs, size_t Rho){
     unsigned long i, r;
     mpz_t rn;
 	 mpz_init(rn);

     for(i = 0; i < prikey->rsub_size; i++){
         if(mpz_cmp_ui(prikey->sk_rsub[i], 1) == 0){
             gen_rrandomb(rn, rs, Rho);
             r = LIMB(rn, 0);
             r = (r % pubkey->pks_size == 0 ? 1UL : r % pubkey->pks_size);
             mpz_add(pubkey->cs[i], pubkey->cs[i], pubkey->pks[r]);
             mpz_mul_ui(rn, rn, 2);
             mpz_add(pubkey->cs[i], pubkey->cs[i], rn);
             mpz_add(pubkey->cs[i], pubkey->cs[i], prikey->sk_rsub[i]);
         }
     }

     time_t t;
     struct tm *lt;
     t = time(NULL);
     lt = localtime(&t);
     strftime(prikey->gen_time, 20, "%Y-%m-%d %H:%M:%S", lt);
     mpz_clear(rn);
 }

 void gen_prikey(__prikey* prikey, randstate rs){
     gen_prime(prikey->sk, prikey->sk_bit_cnt, rs);
     randomize_ss(prikey->sk_rsub, prikey->rsub_hw, prikey->rsub_size);
 }

 void gen_pubkey(__pubkey_set* pubkey, __prikey* prikey, __sec_setting* para, randstate rs, int model){
     int i;
     mpz_t* qs;
     mpz_t rn;
 	 mpz_init(rn);
     qs = (mpz_t*)malloc(para->tau * sizeof(mpz_t));
     getQs(qs, prikey->sk, pubkey->pk_bit_cnt, pubkey->pks_size, para->lam, rs);

     for(i = 0; i < pubkey->pks_size; i++){
         gen_rrandomb(rn, rs, para->rho);
         if(i == 0){
             mpz_mul(pubkey->pks[i], prikey->sk, qs[i]);
             mpz_set(pubkey->x0,pubkey->pks[i]);
         }else{
             mpz_mul(pubkey->pks[i], prikey->sk, qs[i]);
             mpz_mul_ui(rn, rn, 2);
             mpz_add(pubkey->pks[i], pubkey->pks[i], rn);
         }
     }

     if(model == 1){
         encrypt_sk(pubkey, prikey, rs, para->Rho);
     }
     time_t t;
     struct tm *lt;
     t = time(NULL);
     lt = localtime(&t);
     strftime(pubkey->gen_time, 20, "%Y-%m-%d %H:%M:%S", lt);
     mpz_clear(rn);


 }
