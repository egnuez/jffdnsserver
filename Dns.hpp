#include <cstdint>
#include <vector>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>
#include <fstream>
#include <arpa/inet.h>

void print_hex(std::vector <uint8_t> out) {

  printf("%zu bytes:\n", out.size());
  for(uint8_t e : out)
    printf("0x%02x ", e);
  printf("\n");

}

// TODO: What about using unorder_map insteaf of map?

namespace dns {

struct Question {

    std::string qName;
    uint16_t qType;
    uint16_t qClass;
    Question(std::string qName, uint16_t qType, uint16_t qClass):
        qName(qName), qType(qType), qClass(qClass) {}

    bool operator == (const Question& r){
        return qName == r.qName && 
            qType == r.qType &&
            qClass == r.qClass;
    }

};

struct Answer {

    std::string aName;
    uint16_t aType;
    uint16_t aClass;
    uint32_t aTTL;

    Answer(std::string aName, uint16_t aType, uint16_t aClass, uint32_t aTTL):
        aName(aName), aType(aType), aClass(aClass), aTTL(aTTL) {}

    virtual void setRData(uint8_t a, uint8_t b, uint8_t c, uint8_t d) = 0;
    virtual std::string rDataToStr() = 0;
    virtual void putRData (uint8_t** out) = 0;

};

struct A_Answer: public Answer {

    uint8_t addr[4];

    A_Answer(std::string aName, uint16_t aType, uint16_t aClass, uint32_t aTTL):
        Answer(aName, aType, aClass, aTTL) {}

    void setRData(uint8_t a, uint8_t b, uint8_t c, uint8_t d){
        addr[0] = a;
        addr[1] = b;
        addr[2] = c;
        addr[3] = d;
    }

    std::string rDataToStr(){
        std::stringstream ip;
        ip  << int(addr[0]) << "." 
            << int(addr[1]) << "." 
            << int(addr[2]) << "." 
            << int(addr[3]);
        return ip.str();
    }

    void putRData (uint8_t** out){

        uint16_t value = 4;
        value = htons(value);
        memcpy(*out, &value, 2);
        *out += 2;

        memcpy(*out, &addr[0], 1); *out += 1;
        memcpy(*out, &addr[1], 1); *out += 1;
        memcpy(*out, &addr[2], 1); *out += 1;
        memcpy(*out, &addr[3], 1); *out += 1;
    }
};

class Cache {

    private:

    std::map<Question*, Answer*> cache;

    std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(' ');
        if (std::string::npos == first){
            return str;
        }
        size_t last = str.find_last_not_of(' ');
        return str.substr(first, (last - first + 1));
    }

    bool is_number(const std::string& s){
        return !s.empty() && std::find_if(s.begin(), 
            s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
    }

    public:

    Cache(){}

    void load(std::string hosts){

        std::string line;
        std::ifstream hfile(hosts);
        std::string domain;
        std::string ip;
        std::string oct;
        uint8_t tip[4];

        if(hfile.is_open()){

            while (getline(hfile, line)){
                line = trim(line);
                if ((line[0] == '#') || (line.size() == 0)) continue;
                std::replace( line.begin(), line.end(), '\t', ' ');
                std::istringstream ss(line);
                getline(ss, ip, ' ');

                while (true){
                    getline(ss, domain, ' ');
                    if (domain != "" ) break;
                }

                std::istringstream sip(ip);

                int i;
                for(i=0; i<4; i++) {
                    getline(sip, oct, '.');
                    if (! is_number(oct)) break;
                    tip[i] = std::stoi(oct);
                }

                if (i==4){
                    Answer* ans = new A_Answer(domain, 1, 1, 0);
                    Question* qst = new Question(domain, 1, 1); 
                    ans->setRData(tip[0], tip[1], tip[2], tip[3]);
                    set(qst, ans);
                }

            }

            hfile.close();

        }

    }

    std::optional<Answer*> get(Question* question){

        for (auto c : cache){
            if(*(c.first) == *question){
                return c.second;
            }
        }

        return {};

    }

    void set(Question* question, Answer* answer){
        cache.insert ( std::pair<Question*, Answer*>(question, answer) );
    }

};

class Package {

    private:

    uint16_t id;
    uint16_t flags;
    uint16_t queCount;
    uint16_t ansCount;
    uint16_t autCount;
    uint16_t addCount;
    std::vector<Question> questions;
    std::vector<Answer*> answers;

    // QR
    
    enum {
        QR_Request = 0,
        QR_Response = 1
    };

    // RCodes
    
    enum {
        Ok_ResponseType = 0,
        FormatError_ResponseType = 1,
        ServerFailure_ResponseType = 2,
        NameError_ResponseType = 3,
        NotImplemented_ResponseType = 4,
        Refused_ResponseType = 5
    };
  
    // Register Types

    enum {
        A_Type = 1,
        NS_Type = 2,
        CNAME_Type = 5,
        SOA_Type = 6,
        PTR_Type = 12,
        MX_Type = 15,
        TXT_Type = 16,
        AAAA_Type = 28,
        SRV_Type = 33
    };
     
    // Op Code 

    enum {
        Question_OpCode = 0,   // standard Question 
        IQuestion_OpCode = 1,  // inverse Question 
        STATUS_OpCode = 2,  // server status request 
        NOTIFY_OpCode = 4,  // request zone transfer 
        UPDATE_OpCode = 5   // change resource records 
    };

    uint8_t* buffer;
    uint8_t* out;

    uint16_t get16bits() {
        uint16_t value;
        memcpy(&value, buffer, 2);
        buffer += 2;
        return ntohs(value);
    }

    void put8bits(uint8_t value) {
        memcpy(out, &value, 1);
        out += 1;
    }

    void put16bits(uint16_t value) {
        value = htons(value);
        memcpy(out, &value, 2);
        out += 2;
    }

    void put32bits(uint32_t value) {
        value = htons(value);
        memcpy(out, &value, 4);
        out += 4;
    }

    void putDomain(std::string domain) {

        const char * start = domain.c_str();
        const char * cursor = start;
        uint8_t cont = 0;
        while( *cursor != 0 ){
            if(*cursor == '.'){
                *out = cont;
                out++;
                memcpy(out, start, cont);
                out += cont;
                start += cont + 1;
                cont = 0;
            }else{
                cont++;
            }
            cursor++;
        }

        *out = cont;
        out ++;
        memcpy(out, start, cont);
        out += cont;

        *out = 0;
        out++;

    }

    std::string decodeDomain() {

        char * name = new char[256];
        uint8_t len;
        int i = 0;

        while(*buffer != 0){
            len = (uint8_t) *buffer;
            buffer++;
            memcpy(name + i, buffer, len);
            buffer += len;
            i += len;
            name[i] = '.';
            i++;
        }
        name[i-1] = 0;
        std::string domain(name);
        delete []name;
        buffer++;
        return domain;

    }

    void parse() {

        id = get16bits();
        flags = get16bits();
        queCount = get16bits();
        ansCount = get16bits();
        autCount = get16bits();
        addCount = get16bits();
        std::string qDomain = decodeDomain();
        uint16_t qType = get16bits();
        uint16_t qClass = get16bits();

        for (int i = 0; i < queCount; ++i){
            questions.push_back(Question(
                qDomain,
                qType,
                qClass
            ));
        }

    }

    public:

    uint8_t getFlagOPCode(){
        return (flags & 0x7800) >> 11;
    }

    void setFlagRCode(uint8_t rcode){
        flags |= (rcode & 0x0F) << 0;
    }

    void setFlagQR(uint8_t qr){
        flags |= (qr & 0x01) << 15;
    }

    Package(uint8_t* buffer):buffer(buffer) {
        parse();
    }

    ~Package() {
        for (Answer* a : answers){
            delete a;
        }
    }

    friend class Resolver;

    void prettyPrint() {

        std::cout << "++++ DNS Package +++++" << std::endl;
        std::cout << "ID: " << id << std::endl;
        std::cout << "FLAG: " << flags << std::endl;
        std::cout << "Question Count: " << queCount << std::endl;
        std::cout << "Answer Count: " << ansCount << std::endl;
        std::cout << "Auth Count: " << autCount << std::endl;
        std::cout << "Additional: " << addCount << std::endl;

        for (Question q : questions){
            std::cout << "Question => "
                << "Name("  << q.qName  << "),"
                << "Type("  << q.qType  << "),"
                << "Class(" << q.qClass << ")" << std::endl;
        }

        for (Answer* a : answers){
            std::cout << "Answer => "
                << "Name("  << a->aName      << "),"
                << "Type("  << a->aType      << "),"
                << "Class(" << a->aClass     << "),"
                << "TTL("   << a->aTTL       << "),"
                << "RData("  << a->rDataToStr()  << ")" << std::endl;
        }

    }

    std::vector<uint8_t> dump() {

        uint8_t* start = new uint8_t[256];
        out = start;

        put16bits(id);
        put16bits(flags); 
        put16bits(queCount);
        put16bits(ansCount);
        put16bits(autCount);
        put16bits(addCount);

        for (Question q : questions){

            putDomain(q.qName);
            put16bits(q.qType);
            put16bits(q.qClass);

        }

        for (Answer* a : answers){

            putDomain(a->aName);
            put16bits(a->aType);
            put16bits(a->aClass);
            put32bits(a->aTTL);
            a->putRData(&out);

        }

        std::vector<uint8_t> res(start, start + (out - start));
        delete[] start;
        return res;
    }

};

class Resolver {
    Cache& cache;
    public:
    Resolver(Cache& cache):cache(cache){}
    void resolve(Package& package) {

        if (package.getFlagOPCode() == Package::Question_OpCode){
            for (Question q : package.questions){
                if (q.qType == Package::A_Type){
                    std::optional<Answer*> ret = cache.get(&q);
                    if(ret){
                        package.answers.push_back(*ret);
                        package.ansCount++;
                    }
                }
            }
        }else{
            package.setFlagRCode(Package::NotImplemented_ResponseType);
        }
        package.setFlagQR(Package::QR_Response);

    }

};

};

/*
int main(){

    dns::Answer* answer1 = new dns::A_Answer("www.site1.com", 1, 1, 60);
    answer1->setRData(1,2,3,4);
    dns::Answer* answer2 = new dns::A_Answer("www.site2.com", 1, 1, 120);
    answer2->setRData(1,2,3,5);

    dns::Cache cache;
    cache.load("/etc/hosts");
    cache.set("wwww.site1.com", answer1);
    cache.set("wwww.site2.com", answer2);

    std::optional<dns::Answer*> res1 = cache.get("wwww.site1.com");
    std::optional<dns::Answer*> res2 = cache.get("wwww.site2.com");
    std::optional<dns::Answer*> res3 = cache.get("pms.gocloud1.com");

    std::cout << (*res1)->rDataToStr() << std::endl;
    std::cout << (*res2)->rDataToStr() << std::endl;
    std::cout << (*res3)->rDataToStr() << std::endl;

    uint8_t trama[] = {
        0xf9,0xc1,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x77,0x77,0x77,0x08,
        0x66,0x61,0x63,0x65,0x62,0x6f,0x6f,0x6b,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01
    };

    dns::Package package(trama, cache);

    package.prettyPrint();
    package.resolve();
    package.prettyPrint();

    std::vector<uint8_t> out = package.dump();
    print_hex(out);

    return 0;

}
*/