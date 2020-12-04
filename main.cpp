#include <iostream>
#include "SSLParse.h"
#include <sys/time.h>

using namespace std;

/**
 * @name SSLParse使用Dome
 * @author Clancy
 * @date 2020/10/09.
 */
int main(int argc, char **argv)
{
    //1.从本地读取数据
    string str1,str2,str3;
    fstream fs1("../cert/GlobalSign Root CA.cer", ios::in | ios::binary);
    if (!fs1.bad())
    {
        fs1.open("../cert/GlobalSign Root CA.cer", ios::in | ios::binary);
        ostringstream oss;
        oss << fs1.rdbuf();
        str1 = oss.str();
        fs1.close();
    }
    SSLInfo sslInfo1;
    sslInfo1.certstring = str1;

    fstream fs2("../cert/GlobalSign Organization Validation CA - SHA256 - G2.cer", ios::in | ios::binary);
    if (!fs2.bad())
    {
        fs2.open("../cert/GlobalSign Organization Validation CA - SHA256 - G2.cer", ios::in | ios::binary);
        ostringstream oss;
        oss << fs2.rdbuf();
        str2 = oss.str();
        fs2.close();
    }
    SSLInfo sslInfo2;
    sslInfo2.certstring = str2;

    fstream fs3("../cert/baidu.com.cer", ios::in | ios::binary);
    if (!fs3.bad())
    {
        fs3.open("../cert/baidu.com.cer", ios::in | ios::binary);
        ostringstream oss;
        oss << fs3.rdbuf();
        str3 = oss.str();
        fs3.close();
    }
    SSLInfo sslInfo3;
    sslInfo3.certstring = str3;//测试非法字符串是否会中断程序

    //2.将数据填入list,注意SSLInfo结构体的path,id,serverIp,client,server,host字段也应在此时填入
    list<SSLInfo> sslInfoList;
    sslInfoList.push_back(sslInfo1);
    sslInfoList.push_back(sslInfo2);
    sslInfoList.push_back(sslInfo3);

    long size = 0;
    size = (long)str1.size() + (long)str2.size() + (long)str3.size();

    //测试函数运行时间
    struct timeval sTime, eTime;


    //3.初始化SSLParse类,该操作在程序中仅执行一次即可
    SSLParse &sslparse = SSLParse::get_instance();
    gettimeofday(&sTime, NULL);
    int i=0;
//    for(;i<10000;++i){
        //4.将组装好的sslInfo结构体列表根据字符串字段解析其他字段内容
        sslparse.getSSLInfos(sslInfoList);
//    }
//    cout<<endl;
//    gettimeofday(&eTime, NULL);
//
//    long exeTime = (eTime.tv_sec-sTime.tv_sec)*1000000+(eTime.tv_usec-sTime.tv_usec); //exeTime 单位是微秒
//    cout<<"循环"<<i<<"次用时:"<<(double)exeTime/1000/1000<<"s("<<exeTime<<"μs)"<<endl;
//    cout<<"速度:"<<(double)(i * size * 8)/exeTime<<"Mb/s("<<((double)(i * size * 8)/exeTime)/1024<<"Gb/s)"<<endl;

    //5.测试输出效果
    for(SSLInfo &sslInfo:sslInfoList){
        cout<<sslInfo.seriallNumber<<endl;
        cout<<sslInfo.legitimacy<<endl;
        cout<<sslInfo.thumbPrint<<endl;
        cout<<sslInfo.issuer<<endl;
        cout<<sslInfo.issuerCountry<<endl;
        cout<<sslInfo.issuerOrganization<<endl;
        cout<<sslInfo.issuerName<<endl;
        cout<<sslInfo.subject<<endl;
        cout<<sslInfo.subjectCountry<<endl;
        cout<<sslInfo.subjectOrganization<<endl;
        cout<<sslInfo.subjectName<<endl;
        cout<<sslInfo.sigAlgName<<endl;
        cout<<sslInfo.publicKey<<endl;
        cout<<sslInfo.notBefore<<endl;
        cout<<sslInfo.notAfter<<endl;
    }
}