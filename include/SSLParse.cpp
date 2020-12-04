//
// Created by Clancy on 2020/9/28.
//
#include "SSLParse.h"

//获取序列号信息
string serial(X509* x509)
{
    ASN1_INTEGER *bs = X509_get_serialNumber(x509);
    static const char hexbytes[] = "0123456789ABCDEF";
    stringstream ashex;
    for(int i=0; i<bs->length; i++)
    {
        ashex << hexbytes[ (bs->data[i]&0xf0)>>4  ] ;
        ashex << hexbytes[ (bs->data[i]&0x0f)>>0  ] ;
    }
    return ashex.str();
}

//获取指纹信息
string thumbprint(X509* x509)
{
    static const char hexbytes[] = "0123456789ABCDEF";
    unsigned int md_size;
    unsigned char md[EVP_MAX_MD_SIZE];
    const EVP_MD * digest = EVP_get_digestbyname("sha1");
    X509_digest(x509, digest, md, &md_size);
    stringstream ashex;
    for(int pos = 0; pos < md_size; pos++)
    {
        ashex << hexbytes[ (md[pos]&0xf0)>>4 ];
        ashex << hexbytes[ (md[pos]&0x0f)>>0 ];
    }
    return ashex.str();
}

//根据X509_NAME获取内容(发行人信息or主题信息)
string _subject_as_line(X509_NAME *subj_or_issuer)
{
    BIO * bio_out = BIO_new(BIO_s_mem());
    X509_NAME_print(bio_out,subj_or_issuer,0);

    BUF_MEM *bio_buf;
    BIO_get_mem_ptr(bio_out, &bio_buf);

    string issuer = string(bio_buf->data, bio_buf->length);
    BIO_free(bio_out);
    return issuer;
}

//获取发行人信息
string issuer_one_line(X509* x509)
{
    return _subject_as_line(X509_get_issuer_name(x509));
}

//获取主题信息
string subject_one_line(X509* x509)
{
    return _subject_as_line(X509_get_subject_name(x509));
}

//获取公钥类型
string public_key_type(X509 *x509)
{
    EVP_PKEY *pkey=X509_get_pubkey(x509);

    int key_type = EVP_PKEY_type(pkey->type);
    EVP_PKEY_free(pkey);
    if (key_type==EVP_PKEY_RSA) return "rsa";
    if (key_type==EVP_PKEY_DSA) return "dsa";
    if (key_type==EVP_PKEY_DH) return "dh";
    if (key_type==EVP_PKEY_EC) return "ecc";
    return "";
}

//asn1日期解析
void _asn1dateparse(const ASN1_TIME *time, int& year, int& month, int& day, int& hour, int& minute, int& second)
{
    const char* str = (const char*) time->data;
    size_t i = 0;
    if (time->type == V_ASN1_UTCTIME) {/* two digit year */
        year = (str[i++] - '0') * 10 + (str[i++] - '0') + (year < 70 ? 2000 : 1900);
    } else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
        year = (str[i++] - '0') * 1000 + (str[i++] - '0') * 100 + (str[i++] - '0') * 10 + (str[i++] - '0');
    }
    month = (str[i++] - '0') * 10 + (str[i++] - '0');
    day = (str[i++] - '0') * 10 + (str[i++] - '0');
    hour = (str[i++] - '0') * 10 + (str[i++] - '0');
    minute = (str[i++] - '0') * 10 + (str[i++] - '0');
    second = (str[i++] - '0') * 10 + (str[i++] - '0');
}

//asn1日期转iso日期
string asn1datetime_isodatetime(const ASN1_TIME *tm)
{
    int year=0, month=0, day=0, hour=0, min=0, sec=0;
    _asn1dateparse(tm,year,month,day,hour,min,sec);

    char buf[25]="";
    snprintf(buf, sizeof(buf)-1, "%04d-%02d-%02d %02d:%02d:%02d GMT", year, month, day, hour, min, sec);
    return string(buf);
}

//解析x509对象获取签名算法
string signature_algorithm(X509 *x509)
{
    int sig_nid = OBJ_obj2nid((x509)->sig_alg->algorithm);
    return string( OBJ_nid2ln(sig_nid) );
}

/**
 * 字符串分割
 * @param s 待分字符串
 * @param seperator 分割符
 * @return 分割后的数组
 */
vector<string> split(const string &s, const string &seperator){
    vector<string> result;
    typedef string::size_type string_size;
    string_size i = 0;

    while(i != s.size()){
        //找到字符串中首个不等于分隔符的字母；
        int flag = 0;
        while(i != s.size() && flag == 0){
            flag = 1;
            for(string_size x = 0; x < seperator.size(); ++x)
                if(s[i] == seperator[x]){
                    ++i;
                    flag = 0;
                    break;
                }
        }
        //找到又一个分隔符，将两个分隔符之间的字符串取出；
        flag = 0;
        string_size j = i;
        while(j != s.size() && flag == 0){
            for(string_size x = 0; x < seperator.size(); ++x)
                if(s[j] == seperator[x]){
                    flag = 1;
                    break;
                }
            if(flag == 0)
                ++j;
        }
        if(i != j){
            result.push_back(s.substr(i, j-i));
            i = j;
        }
    }
    return result;
}

//去除字符串前面的空格
void trim(string& s){
    if(!s.empty()){
        s.erase(0,s.find_first_not_of(" "));
    }
}

//发行人部分拆分
void issuer_parse(vector<string>& vector,SSLInfo& sslInfo){
    for(string str:vector){
        std::vector<string> v = split(str,"=");
        trim(v[0]);
        if("C"==v[0])
            sslInfo.issuerCountry = v[1];
        else if("CN"==v[0])
            sslInfo.issuerName = v[1];
        else if("O"==v[0])
            sslInfo.issuerOrganization = v[1];
    }
}

//主题部分拆分
void subject_parse(vector<string>& vector,SSLInfo& sslInfo){
    for(string str:vector){
        std::vector<string> v = split(str,"=");
        trim(v[0]);
        if("C"==v[0])
            sslInfo.subjectCountry = v[1];
        else if("CN"==v[0])
            sslInfo.subjectName = v[1];
        else if("O"==v[0])
            sslInfo.subjectOrganization = v[1];
    }
}

//封装SSLInfo结构体
void packageSSLInfoByX509(SSLInfo& sslInfo,X509* x509){
    //序列号
    sslInfo.seriallNumber = serial(x509);
    //指纹
    sslInfo.thumbPrint = thumbprint(x509);
    //发行人
    sslInfo.issuer = issuer_one_line(x509);
    vector<string> issuer_v = split(sslInfo.issuer, ",");
    issuer_parse(issuer_v,sslInfo);

    //主题
    sslInfo.subject = subject_one_line(x509);
    vector<string> subject_v = split(sslInfo.subject, ",");
    subject_parse(subject_v,sslInfo);

    //用于该证书签名算法的名称
    sslInfo.sigAlgName = signature_algorithm(x509);
    //公钥类型
    sslInfo.publicKey = public_key_type(x509);
    //不早于
    sslInfo.notBefore = asn1datetime_isodatetime(X509_get_notBefore(x509));
    //不晚于
    sslInfo.notAfter = asn1datetime_isodatetime(X509_get_notAfter(x509));

//    //输出
//    cout<<sslInfo.seriallNumber<<endl;
//    cout<<sslInfo.thumbPrint<<endl;
//    cout<<sslInfo.issuer<<endl;
//    cout<<sslInfo.issuerCountry<<endl;
//    cout<<sslInfo.issuerOrganization<<endl;
//    cout<<sslInfo.issuerName<<endl;
//    cout<<sslInfo.subject<<endl;
//    cout<<sslInfo.subjectCountry<<endl;
//    cout<<sslInfo.subjectOrganization<<endl;
//    cout<<sslInfo.subjectName<<endl;
//    cout<<sslInfo.sigAlgName<<endl;
//    cout<<sslInfo.publicKey<<endl;
//    cout<<sslInfo.notBefore<<endl;
//    cout<<sslInfo.notAfter<<endl;
}

//将二进制字符串转换为base64并添加证书头尾
inline string toBase64(string& str){
    //将字符串转换为base64
    string base64_str = base64_encode(
            reinterpret_cast<const unsigned char*>
            (str.c_str()),str.length());
    //给base64字符串添加头尾
    string result = "-----BEGIN CERTIFICATE-----\n";
    result.append(base64_str.append("\n-----END CERTIFICATE-----"));
    return result;
}

//加载根证书文件
void SSLParse::loadRootCerts(){
    //打开目录
    DIR* dir = opendir(rootCertPath.c_str());
    if (dir == NULL){
        //LOG(ERROR)<<"open dir error!"<<endl;
        cout<<"open dir error!"<<endl;
        return;
    }
    //目录索引结构体
    struct dirent* entry;
    //从一个目录循环读取一个新的文件
    while ( (entry=readdir(dir)) != NULL)
    {
        //.和..不做读取
        if(0 != strcmp(".",entry->d_name) && 0 != strcmp("..",entry->d_name)){
            string str = "";
            string rootCertPaths = rootCertPath;
            rootCertPaths.append(entry->d_name);
            fstream fs(rootCertPaths, ios::in | ios::binary);
            if (!fs.bad())
            {
                fs.open(rootCertPaths, ios::in | ios::binary);
                ostringstream oss;
                oss << fs.rdbuf();
                str = oss.str();
                fs.close();
            } else{
                //LOG(ERROR)<<rootCertPaths<<" open fail!"<<endl;
                cout<<rootCertPaths<<" open fail!"<<endl;
                continue;
            }
            //分配BIO缓冲区
            BIO *bio_mem = BIO_new(BIO_s_mem());
            //将证书base64内容放入BIO的缓冲区
            BIO_puts(bio_mem,toBase64(str).c_str());
            //将BIO缓冲区的内容转换为X509对象
            X509 * rootCert = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
            if(rootCert != NULL){
                //LOG(INFO)<<entry->d_name<<endl;
                cout<<entry->d_name<<endl;
                //将被信任的证书加入信任链
                X509_STORE_add_cert(certChain,rootCert);
            }
            //释放X509对象空间
            X509_free(rootCert);
            //释放BIO缓冲区
            BIO_free(bio_mem);
            bio_mem = NULL;
        }
    }
    //关闭目录
    closedir(dir);
}

//证书解析构造函数
SSLParse::SSLParse() {
    //根证书存放目录
    rootCertPath = ROOT_CERT_PATH;
    //初始化证书链
    certChain = X509_STORE_new();
    //加载根证书文件
    loadRootCerts();
    //为证书链上下文分配内存
    ctx = X509_STORE_CTX_new();
    //LOG(INFO)<<"SSLParse start!"<<endl;
    cout<<"SSLParse start!"<<endl;
}

//析构函数
SSLParse::~SSLParse() {
    //释放根证书链及上下文内存
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(certChain);
    //LOG(INFO)<<"SSLParse end!"<<endl;
    cout<<"SSLParse end!"<<endl;
}

//根据证书结构体字符串字段解析证书详情
void SSLParse::getSSLInfos(list<SSLInfo>& sslInfos){
    //加载加密算法函数和单向散列算法函数
    OpenSSL_add_all_algorithms();
    //该组证书是否有效(合法)默认非法检测出合法则为合法
    bool isLEGAL = false;

    //根据与根证书对比合法的证书建立合法证书链
    X509_STORE * legalCertChain = NULL;
    //合法证书链上下文
    X509_STORE_CTX *legalctx = NULL;
    //初始化合法证书链
    legalCertChain = X509_STORE_new();
    //为合法证书链上下文分配内存
    legalctx = X509_STORE_CTX_new();

    //循环遍历解析证书字符串数组,完成证书二进制字符串解析工作，并判断是否在根证书链中
    for(SSLInfo &sslInfo:sslInfos){
        //分配BIO缓冲区
        BIO *bio_mem = BIO_new(BIO_s_mem());
        //将证书base64内容放入BIO的缓冲区
        BIO_puts(bio_mem,toBase64(sslInfo.certstring).c_str());
        //将BIO缓冲区的内容转换为X509对象
        X509 * x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
        //判断字符串是否是合法证书
        if(NULL == x509){
            sslInfo.legitimacy = "unlegal";
        }else{
            //与根证书对比判断是否有效
            bool isValid = verify(x509);
            //该组证书是否存在合法证书
            if(isValid){
                //将合法标志位置为true
                isLEGAL = true;
                sslInfo.legitimacy = "legal";
                //将与根证书验证成功的证书放入合法证书链
                X509_STORE_add_cert(legalCertChain,x509);
                //通过X509封装SSLInfo对象
                packageSSLInfoByX509(sslInfo,x509);
            }else{
                //无法与根证书匹配的合法性设置为不确定
                sslInfo.legitimacy = "indeterminate";
                //通过X509封装SSLInfo对象
                packageSSLInfoByX509(sslInfo,x509);
            }
        }
        //释放BIO缓冲区空间
        BIO_free(bio_mem);
        //释放X509对象空间
        X509_free(x509);
    }

    //如果该组与根证书匹配无合法证书，则整组非法。
    if(!isLEGAL){
        for(SSLInfo &sslInfo:sslInfos){
            sslInfo.legitimacy = "unlegal";
        }
    }else{
        //递归判断上层证书是否合法，并生成合法证书链
        check(sslInfos,legalCertChain,legalctx);
        //判断合法性不确定的证书是否在合法证书链中
        for(SSLInfo &sslInfo:sslInfos){
            if(!sslInfo.legitimacy.empty() && sslInfo.legitimacy.compare("indeterminate")){
                //分配BIO缓冲区
                BIO *bio_mem = BIO_new(BIO_s_mem());
                //将证书base64内容放入BIO的缓冲区
                BIO_puts(bio_mem,toBase64(sslInfo.certstring).c_str());
                //将BIO缓冲区的内容转换为X509对象
                X509 * x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
                //初始化合法证书链上下文，legalCertChain是合法证书链，x509是要被验证的证书
                X509_STORE_CTX_init(legalctx,legalCertChain,x509,NULL);
                //验证证书，根据返回值可以确认X509证书是否有效
                int nX509Verify = X509_verify_cert(legalctx);
                if (1 != nX509Verify ){
                    //将证书信息合法值置为非法
                    sslInfo.legitimacy = "unlegal";
                } else {
                    //将证书信息合法值置为合法
                    sslInfo.legitimacy = "legal";
                }
                //清空合法证书链上下文
                X509_STORE_CTX_cleanup(legalctx);
                //释放x509对象空间
                X509_free(x509);
                //释放BIO缓冲区空间
                BIO_free(bio_mem);
            }
        }
        //合法释放合法证书链内存
        X509_STORE_CTX_free(legalctx);
        X509_STORE_free(legalCertChain);
    }

    //防止OpenSSL_add_all_algorithms()出现内存泄漏
    CONF_modules_unload(1);    //for conf
    EVP_cleanup();                 //For EVP
    CRYPTO_cleanup_all_ex_data();  //generic
}

//验证证书是否在根证书链中
bool SSLParse::verify(X509* x509){
    //初始化证书链上下文，certChain是证书链，cert是要被验证的证书
    X509_STORE_CTX_init(ctx,certChain,x509,NULL);
    //验证证书，根据返回值可以确认X509证书是否有效
    int nX509Verify = X509_verify_cert(ctx);
    if (1 != nX509Verify ){
        //无效代码
        long nCode = X509_STORE_CTX_get_error(ctx);
        //无效原因
        const char * pChError = X509_verify_cert_error_string(nCode);
        cout<<"error code:"<<nCode<<";"<<pChError<<endl;
        X509_STORE_CTX_cleanup(ctx);
        return false;
    }
    X509_STORE_CTX_cleanup(ctx);
    return true;
}

//递归判断上层证书是否合法，合法则放入合法证书链中，递归结束则将会话中所有有效证书放入合法证书链中。
bool SSLParse::check(list<SSLInfo> sslInfos,X509_STORE * legalCertChain,X509_STORE_CTX *legalctx){
    for(SSLInfo sslInfo:sslInfos){
        if(!sslInfo.legitimacy.empty() && sslInfo.legitimacy.compare("indeterminate")){
            //分配BIO缓冲区
            BIO *bio_mem = BIO_new(BIO_s_mem());
            //将证书base64内容放入BIO的缓冲区
            BIO_puts(bio_mem,toBase64(sslInfo.certstring).c_str());
            //将BIO缓冲区的内容转换为X509对象
            X509 * x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
            //与当前会话合法证书链对比判断是否有效
            //初始化合法证书链上下文，legalCertChain是证书链，x509是要被验证的证书
            X509_STORE_CTX_init(legalctx,legalCertChain,x509,NULL);
            //验证证书，根据返回值可以确认X509证书是否有效
            int nX509Verify = X509_verify_cert(legalctx);
            //清除合法证书链上下文
            X509_STORE_CTX_cleanup(legalctx);
            //释放BIO缓冲区空间
            BIO_free(bio_mem);
            if (1 != nX509Verify ){
                //释放x509对象内存
                X509_free(x509);
                //删除链中该元素
                sslInfos.remove(sslInfo);
                //递归向下查找
                return check(sslInfos,legalCertChain,legalctx);
            } else {
                //与合法证书链验证通过则将该证书x509对象放入合法证书链中
                X509_STORE_add_cert(legalCertChain,x509);
                //释放x509对象内存
                X509_free(x509);
                return true;
            }
        }
    }
    return true;
}
