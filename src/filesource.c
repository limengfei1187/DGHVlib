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
 #include <unistd.h>

 static int gen_pubkey_header(__pubkey_set* pubkey, char* header, int lines){
     int ret = 0;
     if(pubkey == NULL || header == NULL){
         return -1;
     }
     char *owner, *hostname;
     hostname = (char*)malloc(256*sizeof(char));
     owner = getlogin();
     gethostname(hostname,256);
     sprintf(header, "subject: test fhe-dghv\nalgorithm: dghv\nsize: %lu\npublic key numbers: %lu\nowner: %s@%s\nTime: %s\nLines: %d",
             pubkey->pk_bit_cnt, pubkey->pks_size, owner, hostname, pubkey->gen_time, lines);
     return ret;
 }

 static int gen_prikey_header(__prikey* prikey, char* header, int lines){
     int ret = 0;
     if(prikey == NULL || header == NULL){
         return -1;
     }
     char *owner, *hostname;
     hostname = (char*)malloc(256*sizeof(char));
     owner = getlogin();
     gethostname(hostname,256);
     sprintf(header, "subject: test fhe-dghv\nalgorithm: dghv\nsize: %lu\nowner: %s@%s\nTime: %s\nLines: %d",
             prikey->sk_bit_cnt, owner, hostname, prikey->gen_time, lines);
     return ret;
 }

 int save_str(char** buffer, int length, const char* filename){
     int ret = 0;
     if(buffer == NULL || length <= -1){
         return -1;
     }
     FILE* out;

     if((out = fopen(filename,"wt")) == NULL){
            fprintf(stderr,"Cannot open security parameter file\n");
     }
     int i;
     char* header = (char*)malloc(2*W*sizeof(char));
     sprintf(header, "Ciphertexts:%d", length);
     ret = fprintf(out, "%s\n", header);
     for(i = 0; i < length - 1; i++){
         ret = fprintf(out, "%lu\n%s\n", strlen(buffer[i]), buffer[i]);
     }
     ret = fprintf(out, "%lu\n%s", strlen(buffer[i]), buffer[i]);

     fclose(out);
     return ret;
 }

 char** read_str(const char* filename){

     if(filename == NULL){
         return NULL;
     }

     FILE* in;
     if((in = fopen(filename,"r")) == NULL){
            fprintf(stderr,"Cannot open %s file\n", filename);
     }
     int len1, len2, ret, i = 0;
     char** buffer = NULL;
     char* header = (char*)malloc(2*W * sizeof(char));

     while(!feof(in)){
         if(i == 0){
             header = fgets(header, 2*W, in);
             sscanf(header, "Ciphertext:%d", &len1);
    	     buffer = (char**)malloc((len1+1) * sizeof(char*));
             buffer[0]= (char*)malloc(2*W * sizeof(char));
             sprintf(buffer[0], "%d", len1);
         }else if(i <= len1) {
             ret = fscanf(in, "%d", &len2);
             buffer[i] = (char*)malloc((len2+W) * sizeof(char));
             ret = fscanf(in, "%s", buffer[i]);
             printf("%d\n",i);
         }
         i++;
     }
     return buffer;
 }

 int save_sec_para(__sec_setting* para, const char* filename){

     int ret = 0;
     if(para == NULL || filename == NULL){
         return -1;
     }
     char* buffer = (char*)malloc(W*8 * sizeof(char));
     sprintf(buffer, "lam:%lu\nrho:%lu\nRho:%lu\neta:%lu\ngam:%lu\nTheta:%lu\ntheta:%lu\nn:%lu\ntau:%lu\nprec:%lu",\
                      para->lam,para->rho,para->Rho,para->eta,para->gam,\
                      para->Theta,para->theta,para->n,para->tau,para->prec);
     FILE *out;
     if((out = fopen(filename,"wt")) == NULL){
            fprintf(stderr,"Cannot open security parameter file\n");
     }

     ret = fprintf(out, "%s\n", buffer);
     free(buffer);
     fclose(out);
     return ret;
 }

 int read_sec_para(__sec_setting* para, const char* filename){
     int ret = 0;
     if(para == NULL || filename == NULL){
         return -1;
     }
     char* buffer = (char*)malloc(W*8 * sizeof(char));
     memset(buffer, '\0', W*8 * sizeof(char));
     FILE *in;
     if((in = fopen(filename,"r")) == NULL){
            fprintf(stderr,"Cannot open security parameter file\n");
     }
     int i = 0;

     while(!feof(in)){
         fgets(buffer + i, W*8, in);
         i = strlen(buffer);
     }

     ret = sscanf(buffer, "lam:%lu\nrho:%lu\nRho:%lu\neta:%lu\ngam:%lu\nTheta:%lu\ntheta:%lu\nn:%lu\ntau:%lu\nprec:%lu",\
                           &(para->lam),&(para->rho),&(para->Rho),&(para->eta),&(para->gam),\
                           &(para->Theta),&(para->theta),&(para->n),&(para->tau),&(para->prec));

     free(buffer);
     fclose(in);
     return ret;

 }

 int save_prikey(__prikey* prikey, const char* prikey_filename){
     int ret = 0;
     if(prikey == NULL || prikey_filename == NULL){
         return -1;
     }

     int length, i;
     FILE *out;
     char** buffer = (char**)malloc(W/8 * sizeof(char*));
     char*  header = (char*)malloc(W*W/2 * sizeof(char));
     char*  base64 = (char*)malloc((prikey->sk_bit_cnt/2) * sizeof(char));

     char s1[] = "---- BEGIN FHE PRIVATE KEY ----";
     char s2[] = "---- END FHE PRIVATE KEY ----";

     ret = format_privatekey_str(prikey, buffer, &length);
     ret = gen_prikey_header(prikey, header, length);

     if((out = fopen(prikey_filename,"wt")) == NULL){
            fprintf(stderr,"Cannot open privatekey file\n");
     }

     fprintf(out, "%s\n", s1);
     fprintf(out, "%s\n", header);
     for(i = 0; i < length; i++){

         base64_encode(buffer[i], strlen(buffer[i]), base64);
         fprintf(out, "%s\n", base64);
     }
     ret = fprintf(out, "%s\n", s2);
     free(base64);
     fclose(out);
     free(header);
     for(i = length - 1; i >= 0; i--)free(buffer[i]);
     return ret;
 }

 int read_prikey(__prikey* prikey, const char* prikey_filename){
     int ret = 0;
     if(prikey == NULL || prikey_filename == NULL){
         return -1;
     }

     FILE* in;
     char tmp[10];
     int i = 0, j = 0, length;
     int base64_len  = prikey->sk_bit_cnt/2;
     int buffer_ilen = prikey->sk_bit_cnt/3;
     char** buffer = (char**)malloc(W/8 * sizeof(char*));
     char*  base64 = (char*)malloc(base64_len * sizeof(char));
     char*  header = (char*)malloc(W*8 * sizeof(char));

     if((in = fopen(prikey_filename,"r"))== NULL){
            fprintf(stderr,"Cannot open privatekey file\n");
     }

     while(!feof(in)){
         if(i < PRIHL){
             header = fgets(header, W*8, in);
             strncpy(tmp, header, 5);
             if(strcmp(tmp, "Lines") == 0){
                 strcpy(tmp, header + 7);
                 sscanf(tmp, "%d\n", &length);
             }
             i++;
         }else{
             if(j == length) break;
             ret = fscanf(in, "%s\n", base64);
             buffer[j] = (char*)malloc(buffer_ilen * sizeof(char));
             memset(buffer[j], '\0', buffer_ilen * sizeof(char));
             base64_decode(base64, strlen(base64), buffer[j]);
             j++;
         }
     }
     format_str_privatekey(buffer, length, prikey);

     free(header);
     free(base64);
     for(i = length - 1; i >= 0; i--) free(buffer[i]);
     free(buffer);
     fclose(in);
     return ret;
 }

 int save_pubkey(__pubkey_set* pubkey, const char* pubkey_filename){
     int ret = 0;
     if(pubkey == NULL || pubkey_filename == NULL){
         return -1;
     }

     int i, length;
     int buffer_len = 2*pubkey->y_size + pubkey->pks_size + 2;
     int base64_len = (pubkey->pk_bit_cnt + W*W*W)/2;

     char** buffer = (char**)malloc(buffer_len * sizeof(char*));
     char*  header = (char*)malloc(W*8 * sizeof(char));
     char*  base64 = (char*)malloc(base64_len * sizeof(char));

     char s1[] = "---- BEGIN FHE PUBLIC KEY ----";
     char s2[] = "---- END FHE PUBLIC KEY ----";

     format_publickey_str(pubkey, buffer, &length);
     gen_pubkey_header(pubkey, header, length);

     FILE *out;
     if((out = fopen(pubkey_filename,"wt"))== NULL){
            fprintf(stderr,"Cannot open privatekey file\n");
     }

     fprintf(out, "%s\n", s1);
     fprintf(out, "%s\n", header);

     for(i = 0; i < length; i++){
         base64_encode(buffer[i], strlen(buffer[i]), base64);
         fprintf(out, "%s\n", base64);
         memset(base64, '\0', base64_len * sizeof(char));
     }
     fprintf(out, "%s\n", s2);

     free(base64);
     fclose(out);
     free(header);
     for(i = length - 1; i >= 0; i--){
         free(buffer[i]);
     }
     free(buffer);
     return ret;
 }

 int read_pubkey(__pubkey_set* pubkey, const char* pubkey_filename){
     int ret = 0;
     if(pubkey == NULL || pubkey_filename == NULL){
         return -1;
     }

     int i = 0, j = 0;
     int base64_len = (pubkey->pk_bit_cnt + W*W*W)/2;
     int buffer_len = 2*pubkey->y_size+pubkey->pks_size+2;
     int buffer_jlen = ((pubkey->pk_bit_cnt/W*W)/4) + W*W*W;

     char** buffer = (char**)malloc(buffer_len * sizeof(char*));
     char*  base64 = (char*)malloc(base64_len * sizeof(char));
     char*  header = (char*)malloc(W*8 * sizeof(char));

     FILE* in;
     if((in = fopen(pubkey_filename,"r"))== NULL){
            fprintf(stderr,"Cannot open privatekey file\n");
     }

     while(!feof(in)){
         if(i < PUBHL){
             header = fgets(header, W*8, in);
             i++;
         }else if(j < buffer_len){

             ret = fscanf(in, "%s", base64);
             buffer[j] = (char*)malloc(buffer_jlen * sizeof(char));
             memset(buffer[j], '\0', buffer_jlen * sizeof(char));
             base64_decode(base64, strlen(base64), buffer[j]);
             j++;
         }else{
             break;
         }
     }
     format_str_publickey(buffer, buffer_len, pubkey);

     free(base64);
     for(i = 0; i < buffer_len; i++) free(buffer[i]);
     free(buffer);
     fclose(in);
     return ret;
 }
