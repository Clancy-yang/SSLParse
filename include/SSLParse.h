//
// Created by Clancy on 2020/9/28.
//

#ifndef SSLPARSE_SSLPARSE_H
#define SSLPARSE_SSLPARSE_H
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstring>

#include <sys/types.h>
#include <vector>
#include <list>
#include <map>
#include <dirent.h>
#include <memory>
#include <mutex>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "base64.h"

#define ROOT_CERT_PATH "../cerRoot/"

using namespace std;

/**
 * @name SSLInfo 证书信息
 * 用于存储解析后的证书信息
 */
typedef struct SSLInfo{
    string seriallNumber;   //序列号
    string path;            //路径
    string id;              //id
    string legitimacy;      //合法性
    string serverIp;        //服务器IP
    string client;          //客户端
    string server;          //服务器
    string host;            //主机
    string thumbPrint;      //指纹
    string issuer;          //发行人
    string issuerName;      //发行人姓名
    string issuerOrganization;//发行组织
    string issuerCountry;   //发行国家
    string sigAlgName;      //用于该证书签名算法的名称
    string subject;         //主题
    string subjectOrganization;//主题单位
    string subjectCountry;  //所在国家
    string subjectName;     //主题名称
    string publicKey;       //公钥
    string notBefore;       //不早于
    string notAfter;        //不晚于
    string certstring;      //证书二进制字符串
    bool operator==(const SSLInfo &sslInfo){
        return (sslInfo.seriallNumber == seriallNumber);
    }
}SSLInfo;

/**
 * @name SSLParse 证书解析类
 * 实例化证书解析类，初始化读取根证书列表。
 *
 * 所用到的特性是在C++11标准中的Magic Static特性：
 * If control enters the declaration concurrently while the variable is being initialized, the concurrent execution shall wait for completion of the initialization.
 * 如果当变量在初始化的时候，并发同时进入声明语句，并发线程将会阻塞等待初始化结束。
 * 这样保证了并发线程在获取静态局部变量的时候一定是初始化过的，所以具有线程安全性。
 * C++静态变量的生存期是从声明到程序结束，这也是一种懒汉式。
 */
class SSLParse{
public:
    SSLParse(const SSLParse&)=delete;
    SSLParse& operator=(const SSLParse&)=delete;
    ~SSLParse();
    //获取证书解析类实例对象
    static SSLParse& get_instance(){
        static SSLParse instance;
        return instance;
    }

    //根据证书字符串数组得到证书内容结构体数组
    void getSSLInfos(list<SSLInfo>&);

private:
    //根证书链
    X509_STORE * certChain;
    //根证书链上下文
    X509_STORE_CTX *ctx;
    //根证书所在目录
    string rootCertPath;
    //构造函数 初始化根证书链
    SSLParse();
    //加载根证书目录的根证书
    void loadRootCerts();
    //验证证书是否在根证书链中
    bool verify(X509*);
    //递归判断上层证书是否合法，并将list中合法证书加入合法证书链中
    bool check(list<SSLInfo>,X509_STORE*,X509_STORE_CTX*);
};


#endif //SSLPARSE_SSLPARSE_H
