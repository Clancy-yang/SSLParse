#include <iostream>
#include "SSLParse.h"

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
    sslInfo3.certstring = "str3";//测试非法字符串是否会中断程序

    //2.将数据填入list,注意SSLInfo结构体的path,id,serverIp,client,server,host字段也应在此时填入
    list<SSLInfo> sslInfoList;
    sslInfoList.push_back(sslInfo1);
    sslInfoList.push_back(sslInfo2);
    sslInfoList.push_back(sslInfo3);

    //3.初始化SSLParse类,该操作在程序中仅执行一次即可
    SSLParse &sslparse = SSLParse::get_instance();
    //4.将组装好的sslInfo结构体列表根据字符串字段解析其他字段内容
    sslparse.getSSLInfos(sslInfoList);

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
