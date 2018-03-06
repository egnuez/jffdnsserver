#include "Dns.hpp"
#define BUF_SIZE 256

int main(){

    /*
    **  Request Example:
    **  Query: 
    **      Name (www.facebook.com) Type (A) Class (IN)
    */

    uint8_t package_request_1[] = {
    0xf9, 0xc1, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77,
    0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x01, 0x00, 0x01 };

    dns::Package PackageRequest1(package_request_1);
	PackageRequest1.prettyPrint();

    /*
    **  Request Example:
    **  Query: 
    **      Name (www.facebook.com) Type (CNAME) Class (IN)
    */

    uint8_t package_request_2[] = {
    0x76, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 
    0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x05, 0x00, 0x01 };

    dns::Package PackageRequest2(package_request_2);
	PackageRequest2.prettyPrint();

    /*
    **  Response Example:
    **  Query:
    **      Name (www.facebook.com) Type (A) Class (IN)
    **  Answer:
    **      Name (www.facebook.com) Type (CNAME) Class (IN) TTL (3238) CNAME (star-mini.c10r.facebook.com)
    **      Name (star-mini.c10r.facebook.com) Type (A) Class (IN) TTL (21) A (157.240.14.35)
    */

    uint8_t package_response_1[] = { 0xf9, 0xc1, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 
    0x03, 0x77, 0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 
    0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 
    0x0c, 0xa6, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69, 0x04, 
    0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 
    0x15, 0x00, 0x04, 0x9d, 0xf0, 0x0e, 0x23 };

	dns::Package PackageResponse1(package_response_1);
	PackageResponse1.prettyPrint();

    /*
    **  Response Example:
    **  Query: 
    **      Name (www.facebook.com) Type (CNAME) Class (IN)
    **  Answer:
    **      Name (www.facebook.com) Type (CNAME) Class (IN) TTL (2422) CNAME (star-mini.c10r.facebook.com)
    **      
    */

    uint8_t package_response_2[] = {
    0x76, 0x06, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 
    0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
    0x00, 0x05, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x09, 0x76, 0x00, 
    0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69, 0x04, 0x63, 0x31, 0x30, 
    0x72, 0xc0, 0x10 };

    dns::Package PackageResponse2(package_response_2);
	PackageResponse2.prettyPrint();

    /*
    ** Create Package Question: Name (www.site1.com) Type (A), Class (IN), 
    */

    dns::Question QuestionSite1("www.site1.com", dns::Package::A_Type, dns::Package::IN_Class);
    dns::Package PackageSite1(0x0111);
    PackageSite1.addQuestion(QuestionSite1);
    PackageSite1.prettyPrint();

    /*
    ** Create Package Question: Name (www.site1.com) Type (CNAME), Class (IN), 
    */
    
    dns::Question QuestionSite2("www.site2.com", dns::Package::CNAME_Type, dns::Package::IN_Class);
    dns::Package PackageSite2(0x0222);
    PackageSite2.addQuestion(QuestionSite2);
    PackageSite2.prettyPrint();

    /*
    ** Create Package Response: Name (www.site2.com) Type (CNAME), Class (IN), 
    */

    dns::Answer* answerSite1 = new dns::A_Answer("www.site1.com", dns::Package::A_Type, dns::Package::IN_Class, 60);
    answerSite1->setRData(192,168,1,1);

    dns::Package PackageResponseSite1(0x0222);
    PackageResponseSite1.addQuestion(QuestionSite1);
    PackageResponseSite1.addAnswer(answerSite1);
    PackageResponseSite1.setFlagQR(dns::Package::QR_Response);
    PackageResponseSite1.prettyPrint();

    /*
    ** Create Package Response: Name (www.site2.com) Type (CNAME), Class (IN), 
    */

    dns::Answer* answerSite2 = new dns::CNAME_Answer("www.site2.com", dns::Package::CNAME_Type, dns::Package::IN_Class, 60);
    answerSite2->setRData("alias.s01.site2.com");

    dns::Package PackageResponseSite2(0x0222);
    PackageResponseSite2.addQuestion(QuestionSite2);
    PackageResponseSite2.addAnswer(answerSite2);
    PackageResponseSite2.setFlagQR(dns::Package::QR_Response);
    PackageResponseSite2.prettyPrint();

    /*
    dns::Cache cache;
    cache.load("/etc/hosts");
    cache.set(question1, answer1);
    cache.set(question2, answer2);

    std::optional<dns::Answer*> res1 = cache.get(question1);
    std::optional<dns::Answer*> res2 = cache.get(question2);
	std::optional<dns::Answer*> res3 = cache.get(question3);
    std::optional<dns::Answer*> res4 = cache.get(question4);

	if(res1)
    	std::cout << (*res1)->rDataToStr() << std::endl;
    else
		std::cout << "q1 not found" << std::endl;
	
	if(res2)
		std::cout << (*res2)->rDataToStr() << std::endl;
	else
		std::cout << "q2 not found" << std::endl;

	if(res3)
		std::cout << (*res3)->rDataToStr() << std::endl;
	else
		std::cout << "q3 not found" << std::endl;

	if(res4)
		std::cout << (*res4)->rDataToStr() << std::endl;
	else
		std::cout << "q4 not found" << std::endl;
    */

}