# DGHVlib
This repository is about the implementation of homomorphic encryption scheme (DGHV).

可以自己编译，进入src文件夹里打开terminal 
          make
就能够编译成静态链接库DGHVlib.a 该同态加密库是在ubuntu环境下完成的。如果使用尽量在linux环境下使用，因为代码中
unsigned long int 类型在windows 占4个字节， linux下占8个字节，而gmp该精度运算库的每个limb占8个字节。在windows
下编译可能会出现结果错误。



#define TOY                   0 // 是个参数级别 参见secstg.h 也可以自己设置 自己设置后需要用
                                 //bool para_valid(__sec_setting* para)验证一下,参数是否合理
 #define SMALL                 1
 #define MEDIUM                2
 #define LARGE                 3

 #define PROB_EXP              50
 #define BASE                  2
 #define PRIHL                 7
 #define PUBHL                 8

 #define W                     (GMP_NUMB_BITS/2)
 #define _LSBMASK              1ul
 #define _MSBMASK              (1ul << (2 * W - 1))
 #define _BOT_N_MASK(n)        ((_LSBMASK << n) - 1)
 #define _TOP_N_MASK(n)        (_BOT_N_MASK(n) << (2 * W - n))

 #define R_N_SHIFT(x, n)       (x >> n)
 #define L_N_SHIFT(x, n)       (x << n)
 #define MP_EXP(x)             (x->_mp_exp)  //获得GMP库中的大浮点数mpf_t 中的_mp_exp 见gmp.h 197行注释
 #define MP_SIZE(x)            (x->_mp_size) //mpf_t 中limbs的数目， 每个limb 是无符号长整形的指针 存放大数中的64位二进制数
 #define MP_PREC(x)            (x->_mp_prec) //mpf_t 中的精度 表示 有_mp_prec个limb 表示小数部分。
 #define MP_ALLOC(x)           (x->_mp_alloc)//mpz_t 大整数中的 limbs 个数
 #define LIMB(x, i)            (((i)<((x)->_mp_size))?((x)->_mp_d[i]):(0L)) //获得mpf_t 或者mpz_t 的第i个limb
 #define LSB(x)                (x & _LSBMASK) //取最低有效位
 #define MSB(x)                (x & _MSBMASK) //取最高有效位
 #define MSBN(x, n)            (x & (_TOP_N_MASK(n))) //最高N位有效位， 需要再次右移 2W-N 位才能正确取到
 #define LSBN(x, n)            (x & (_BOT_N_MASK(n))) //最低N位有效位
 #define MIN_ETA(x)            (21 * x + 50) // 当参数 中n=5 时的最小秘钥长度。


// 参数类型
 typedef struct securitySetting{
     size_t lam;  //安全参数
     size_t Rho;  //公钥中噪音
     size_t rho;  //加密噪音
     size_t eta;  //秘钥长度
     size_t gam;  //公钥长度
     size_t Theta; // 稀疏子集的位数
     size_t theta; // 稀疏子集的汉明权重
     size_t tau;   //公钥个数
     size_t prec;  // yi小数点后的精度
     size_t n;     //bootstrapping中取小数点后n位， 即c*yi 取小数点后n位参与密文刷新。

 }__sec_setting;

//私钥类型
 typedef struct privatekey{
     mpz_t sk;  // 私钥
     mpz_t* sk_rsub; // 稀疏子集
     size_t rsub_size; // 稀疏子集大小
     size_t rsub_hw;   //稀疏子集汉明权重
     size_t sk_bit_cnt;//私钥比特长度
     char gen_time[20];// 死要产生时间
 }__prikey;

 typedef struct publickeyset{
     mpz_t x0; //最长公钥 模x0，控制密文长度
     mpz_t *pks; // 公钥集合
     mpz_t *cs;  // 加密后的稀疏子集
     mpf_t *y;   // 1/p = y1+y2+...
     size_t pks_size; // 工要个数
     size_t y_size;   //yi 个数
     size_t pk_bit_cnt; // 公钥比特长度
     char gen_time[20]; // 产生时间
 }__pubkey_set;

//密文类型
 typedef struct ciphertext{
     mpz_t c; // 密文
     mpf_t *z;  //扩展后的密文 zi= c*yi
     size_t z_size; // zi的个数
 }__cit;   //ciphertext

//汉明权重计算表

 typedef struct hamming_weight_table{
     mpz_t **table;
     size_t x;
     size_t y;
 }__hw_table;

//秘闻刷新计算表
 typedef struct evaluation_table{
     mpz_t **table;
     size_t x;
     size_t y;
 }__ev_table;

 typedef gmp_randstate_t randstate;  // 随机状态
 typedef __prikey*       c_prikey;   // 秘钥指针类型
 typedef __pubkey_set*   c_pubkeys;  // 公钥指针类型
 typedef __sec_setting*  c_parameters; // 参数指针类型
 typedef __cit*          c_cit;       //密文指针类型


/**************** Security Parameters Setting.  ****************/
//secstg.c

//初始化参数
 void init_sec_para(__sec_setting** para);
//初始化默认参数 TOY, SMALL, MEDIUM, LARGE四个级别 可以自己设置 具体参数在secstg.c文件中
 void set_default_para(__sec_setting* para, int level);
//验证参数设置是否合理
 bool para_valid(__sec_setting* para);

/****************  Initialized Key.  ****************/
//key.c

//初始化私钥， 需要用到参数初始化，因此在初始化私钥之前必须初始化参数，并且吧参数设置好
 void init_sk(__prikey** prikey, __sec_setting* para);
//初始化公钥集合
 void init_pkset(__pubkey_set** pubkey, __sec_setting* para);
//释放私钥
 void clear_sk(__prikey* prikey);
//释放公钥
 void clear_pkset(__pubkey_set* pubkey);


/****************  Generated Ramdom Number.  ****************/
//gen_random.c

//获得随机种子
 unsigned long get_seed();
//讲随机种子与随机状态结合，为产生随机数 做准备
//随机状态类型 randstate，seed随机种子
 void set_randstate(randstate rs, unsigned long seed);
 //产生不超过n bit位的随机数
 //rn：mpz_t类型的随机数， rs 随机状态， n 随机数长度
 void gen_rrandomb(mpz_t rn, randstate rs, unsigned long n);
//产生不超过大整数ub的随机数
 void gen_urandomm(mpz_t rn, randstate rs, mpz_t ub);


 /****************  Generated Private Key & Public Key.  ****************/
//gen_key.c
//产生素数 素数p，n 随机数长度， rs 随机状态
 void gen_prime(mpz_t p, size_t n, randstate rs);
//大整数 n/d 取商q的四舍五入值
 void div_round_q(mpz_t q, mpz_t  n, mpz_t d);
//判断b是否是 a rough, a-rough： b的最小素因子不超过a
 bool is_a_rough(mpz_t a, mpz_t b);
// 产生公钥中的Q集合 p是秘钥， mpz_t* q是得到的Q集合
 void getQs(mpz_t* q, mpz_t p, size_t gam, size_t tau, size_t lam, randstate rs);
 //随机产生稀疏子集 ss是稀疏子集  ss_hw稀疏子集的汉明权重 ss_size稀疏子集的大小
 void randomize_ss(mpz_t* ss, size_t ss_hw, size_t ss_size);
//随机产生 ss_hw个 yy 使得 ∑yyi = 「(2^prec)/p」(此处「 」取近似整数) 为产生1/p=∑yi做准备
 void randomize_sk(mpz_t* yy, mpz_t p, size_t ss_hw, size_t prec);
//把秘钥 p 转换成 1/p=∑yi 存放在公钥pubkey中
 void expand_p2y(__pubkey_set* pubkey, __prikey* prikey, size_t prec, randstate rs);
// 产生 私钥prikey
 void gen_prikey(__prikey* prikey, randstate rs);
//产生公钥pubkey，产生公钥过程中需要用到私钥prikey，参数para 随机状态rs model表示是否对秘钥中的稀疏子集加密 放到公钥中 1表示是 0 表示否
 void gen_pubkey(__pubkey_set* pubkey, __prikey* prikey, __sec_setting* para, randstate rs, int model);


/****************  Initialized Ciphertext.  ****************/
//ciphertext.c

//初始化密文 Theta是参数中的Theta
 void init_cit(__cit** ciph, size_t Theta);
//扩展密文 zi = c*yi存放在密文ciph->z[i]中， pubkey位公钥集合
 void expend_cit(__cit* ciph, __pubkey_set* pubkey);
//释放密文
 void clear_cit(__cit* ciph);


/****************  Encrypt & Decrypt.  ****************/
//crypto.c

//DGHV 加密 ciphertext加密后的密文， plaintext：明文 表示0,1位（同态加密按照位加密）pubkey：公钥 para：参数 rs：随机状态
 void DGHV_encrypt(__cit* ciphertext, unsigned long plaintext, __pubkey_set* pubkey, __sec_setting* para, randstate rs);
//解密 ciphertext：解密的密文， prikey私钥
 unsigned long DGHV_decrypt(__cit* ciphertext, __prikey* prikey);


/****************  Squashed Decrypt Circuitry.  ****************/
//squa_dec.c 这部分用不到就不说了， 这部分是压缩解密电路所用的数据结构和函数
 void init_hw_table(__hw_table** hwtable, size_t x, size_t y);

 void init_ev_table(__ev_table** evtable, size_t x, size_t y);

 void clear_hw_table(__hw_table* hwtable);

 void clear_ev_table(__ev_table* evtable);

 void set_ev_table(unsigned long i, mpf_t z, __ev_table* ev_table);

 void get_hw(int i, __ev_table* ev_table, __sec_setting* para);

 unsigned long get_ciph_lsb(__cit* ciph);

 unsigned long get_ciphdivp_lsb(__cit* ciph, __prikey* prikey, __sec_setting* para);

/****************  Evaluated Addition & Multiplication.  ****************/
//eval_oper.c

//同态加法， 并把相加得到的结果密文sum 进行扩展 zi = c*yi（如果不对这个密文刷新就不需要扩展，因此下面提供了不带扩展功能的同台加法操作）
 void evaluate_add_ex(__cit* sum, __cit* c1, __cit* c2, __pubkey_set* pubkey);
//不带密文扩展的同态加密法操作
 void evaluate_add(__cit* sum, __cit* c1, __cit* c2, mpz_t x0);
//带扩展的同台乘法操作
 void evaluate_mul_ex(__cit* product, __cit* c1, __cit* c2, __pubkey_set* pubkey);
//不带扩展的同台乘法操作
 void evaluate_mul(__cit* product, __cit* c1, __cit* c2, mpz_t x0);

/****************  Bootstrapping.  ****************/
//bootstrapping.c

//计算第i列的汉明权重，就是那个进位（这里的进位都是用密文表示的）
 void c_get_hw(int i, __ev_table* ev_table, __sec_setting* para, mpz_t x0);
//取密文ciph最低有效位，对最低有效位加密 得到的密文存储在cc中
 void c_get_ciph_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);
//取c/p = 「c*∑si*yi」+（误差不写了打不出来，哈哈哈）的最低有效位，就是计算出来 小数点前一位和后一位的密文 在求和 就是他的最低有效位的密文
//ciph需要计算的密文 cc计算的最低有效位的密文
 void c_get_ciphdivp_lsb(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para);
// 密文刷新 cc刷新的密文， ciph被刷新的密文
 void bootstrap(__cit* cc, __cit* ciph, __pubkey_set* pubkey, __sec_setting* para, randstate rs);
