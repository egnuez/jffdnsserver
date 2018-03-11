#include <cstdint>
#include <vector>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <algorithm>
#include <fstream>
#include <stack>
#include <ctime>
#include <sys/socket.h>
#include <arpa/inet.h>

#define BUF_SIZE 256

void print_hex(std::vector <uint8_t> out) {

  printf("%zu bytes:\n", out.size());
  for(uint8_t e : out)
    printf("0x%02x ", e);
  printf("\n");

}

namespace dns {

struct Question {

    std::string qName;
    uint16_t qType;
    uint16_t qClass;
    Question(std::string qName, uint16_t qType, uint16_t qClass):
        qName(qName), qType(qType), qClass(qClass) {}

    Question(const Question &p):
        qName(p.qName), qType(p.qType), qClass(p.qClass) {}

    bool operator == (const Question& r) const {
        return qName == r.qName && 
            qType == r.qType &&
            qClass == r.qClass;
    }

    bool operator < (const Question &r) const {
        return true;
    }

};

struct Answer {

    std::string aName;
    uint16_t aType;
    uint16_t aClass;
    uint32_t aTTL;

    Answer(std::string aName, uint16_t aType, uint16_t aClass, uint32_t aTTL):
        aName(aName), aType(aType), aClass(aClass), aTTL(aTTL) {}

    virtual void setRData(uint8_t a, uint8_t b, uint8_t c, uint8_t d){};
    virtual void setRData(std::string domain){};
    virtual std::string rDataToStr(){
        return std::string("default");
    };
    virtual void putRData (uint8_t** out) = 0;
    virtual Answer * copy() = 0;
};

struct A_Answer: public Answer {

    uint8_t addr[4];

    A_Answer(std::string aName, uint16_t aType, uint16_t aClass, uint32_t aTTL):
        Answer(aName, aType, aClass, aTTL) {}

    Answer * copy(){
        Answer * answer = new A_Answer(aName, aType, aClass, aType);
        answer->setRData(addr[0],addr[1],addr[2],addr[3]);
        return answer;
    }

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

struct CNAME_Answer: public Answer {

    std::string domain;

    CNAME_Answer(std::string aName, uint16_t aType, uint16_t aClass, uint32_t aTTL):
        Answer(aName, aType, aClass, aTTL) {}

    Answer * copy(){
        Answer * answer = new A_Answer(aName, aType, aClass, aType);
        answer->setRData(domain);
        return answer;
    }

    void setRData(std::string domain){
        this->domain = domain;
    }

    std::string rDataToStr(){
        return domain;
    }

    void putRData (uint8_t** out){

        int16_t value = domain.size();
        value = htons(value);
        memcpy(*out, &value, 2);
        *out += 2;
        memcpy(*out, domain.c_str(), value); *out += 1;
    
    }

};

class Cache {

    typedef std::pair<std::vector<Answer*>, time_t> Element;

    private:
    std::map<Question, Element> cache;

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
                    Question qst(domain, 1, 1); 
                    ans->setRData(tip[0], tip[1], tip[2], tip[3]);
                    set(qst, std::vector<Answer*> (1, ans));
                }

            }

            hfile.close();

        }

    }

    std::optional<std::vector<Answer*>> get(Question question){

        for (auto c : cache){
            if(c.first == question){
                return c.second.first;
            }
        }

        return {};

    }

    void set(Question question, std::vector<Answer*> answers){
        Element element(answers, 0);
        cache.insert (
            std::pair<Question, Element> (question, element)
        );
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
    public:

    enum {
        QR_Request = 0,
        QR_Response = 1
    };

    std::string qr2string(uint8_t qr){
        std::string res("Unknown");
        switch(qr){
            case 0:
                res = "Request";
                break;
            case 1:
                res = "Response";
                break;
        }
        return res;
    }

    // RCodes
    
    enum {
        Ok_ResponseType = 0,
        FormatError_ResponseType = 1,
        ServerFailure_ResponseType = 2,
        NameError_ResponseType = 3,
        NotImplemented_ResponseType = 4,
        Refused_ResponseType = 5
    };

    std::string rcodes2string(uint8_t rcode){
        std::string res("Unknown");
        switch(rcode){
            case 0:
                res = "Ok_ResponseType";
                break;
            case 1:
                res = "FormatError_ResponseType";
                break;
            case 2:
                res = "ServerFailure_ResponseType";
                break;
            case 3:
                res = "NameError_ResponseType";
                break;
            case 4:
                res = "NotImplemented_ResponseType";
                break;
            case 5:
                res = "Refused_ResponseType";
                break;
        }
        return res;
    }

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

    std::string rtypes2string(uint8_t rtype){
        std::string res("Unknown");
        switch(rtype){
            case 1:
                res = "A";
                break;
            case 2:
                res = "NS";
                break;
            case 5:
                res = "CNAME";
                break;
            case 6:
                res = "SOA";
                break;
            case 12:
                res = "PTR";
                break;
            case 15:
                res = "MX";
                break;
            case 16:
                res = "TXT";
                break;
            case 28:
                res = "AAAA";
                break;
            case 33:
                res = "SRV";
                break;
        }
        return res;
    }

    // Classes

    enum {
        IN_Class = 1
    };

    std::string classes2string(uint8_t class_){
        std::string res("Unknown");
        switch(class_){
            case 1:
                res = "IN";
                break;
        }

        return res;
    }

    private:
     
    // Op Code 

    enum {
        Question_OpCode = 0,   // standard Question 
        IQuestion_OpCode = 1,  // inverse Question 
        STATUS_OpCode = 2,  // server status request 
        NOTIFY_OpCode = 4,  // request zone transfer 
        UPDATE_OpCode = 5   // change resource records 
    };

    std::string opcode2string(uint8_t opcode){
        std::string res("Unknown");
        switch(opcode){
            case 0:
                res = "Question";
                break;
            case 1:
                res = "IQuestion";
                break;
            case 2:
                res = "Status";
                break;
            case 4:
                res = "Notify";
                break;
            case 5:
                res = "Update";
                break;
        }
        return res;
    }

    uint8_t* start;
    uint8_t* buffer;
    uint8_t* out;

    uint8_t get8bits() {
        uint8_t value;
        memcpy(&value, buffer, 1);
        buffer += 1;
        return value;
    }

    uint16_t get16bits() {
        uint16_t value;
        memcpy(&value, buffer, 2);
        buffer += 2;
        return ntohs(value);
    }

    uint32_t get32bits() {
        uint32_t value;
        memcpy(&value, buffer, 4);
        buffer += 4;
        return ntohl(value);
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
        std::stack<uint8_t*> pointers;

        while(*buffer != 0){

            len = (uint8_t) *buffer;

            // Is a offset of before name appaer
            if((len >> 6) == 0x03){
            
                buffer++;
                uint16_t offset = (uint16_t) *buffer;
                offset &= 0x3FFF;
                buffer++;
                pointers.push(buffer);
                buffer = start + offset;

            }else{

                buffer++;
                memcpy(name + i, buffer, len);
                buffer += len;
                i += len;
                name[i] = '.';
                i++;
            }

        }

        if(*buffer == 0)
            buffer++;

        while(!pointers.empty()){
            buffer = pointers.top();
            pointers.pop();
        }

        name[i-1] = 0;
        std::string domain(name);
        delete []name;
        return domain;
        
    }

    void parse() {

        id =        get16bits();
        flags =     get16bits();
        queCount =  get16bits();
        ansCount =  get16bits();
        autCount =  get16bits();
        addCount =  get16bits();

        for (int i = 0; i < queCount; ++i){

            std::string qDomain = decodeDomain();
            uint16_t qType = get16bits();
            uint16_t qClass = get16bits();

            questions.push_back(Question(
                qDomain,
                qType,
                qClass
            ));
        }

        for (int i = 0; i < ansCount; ++i){
  
            std::string Domain =    decodeDomain();
            uint16_t Type =         get16bits();
            uint16_t Class =        get16bits();
            uint32_t TTL =          get32bits();
            uint16_t Lenght =       get16bits();

            switch(Type){

            case A_Type: {
                
                uint8_t oct1 = get8bits();
                uint8_t oct2 = get8bits();
                uint8_t oct3 = get8bits();
                uint8_t oct4 = get8bits();
                
                Answer* ans = new A_Answer(
                    Domain,
                    Type,
                    Class,
                    TTL
                );

                ans->setRData(oct1, oct2, oct3, oct4);

                answers.push_back(ans);
                break;
            }

            case CNAME_Type: {

                std::string cname = decodeDomain();
                
                Answer* ans = new CNAME_Answer(
                    Domain,
                    Type,
                    Class,
                    TTL
                );

                ans->setRData(cname);
                answers.push_back(ans);
        
                break;
            }

            }
        
        }

    }

    public:

    uint16_t getAutCount(){
        return ansCount;
    }

    uint8_t getFlagQR(){
        return (flags & 0x8000) >> 15;
    }

    uint8_t getFlagOPCode(){
        return (flags & 0x7800) >> 11;
    }

    uint8_t getRCode(){
        return (flags & 0x000F);
    }

    void setFlagRCode(uint8_t rcode){
        flags |= (rcode & 0x0F) << 0;
    }

    void setFlagQR(uint8_t qr){
        flags |= (qr & 0x01) << 15;
    }

    Package(uint8_t* buffer):buffer(buffer), start(buffer) {
        parse();
    }

    Package(uint16_t id) {
        this->id = id;
        this->flags = 0;
        this->queCount = 0;
        this->ansCount = 0;
        this->autCount = 0;
        this->addCount = 0;
    }

    void addQuestion(Question question){
        this->questions.push_back(question);
        this->queCount++;
    }

    void addAnswer(Answer* answer){
        this->answers.push_back(answer);
        this->ansCount++;
    }

    std::vector<Answer*> getAnswers(){
        return answers;
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
        std::cout << "\t" << qr2string(getFlagQR()) << std::endl;
        std::cout << "\t" << opcode2string(getFlagOPCode()) << std::endl;
        std::cout << "\t" << rcodes2string(getRCode()) << std::endl;
        std::cout << "\t." << std::endl;
        std::cout << "\t." << std::endl;
        std::cout << "\t." << std::endl;
        std::cout << "Question Count: " << queCount << std::endl;
        std::cout << "Answer Count: " << ansCount << std::endl;
        std::cout << "Auth Count: " << autCount << std::endl;
        std::cout << "Additional: " << addCount << std::endl;

        for (Question q : questions){
            std::cout << "Question => "
                << "Name("  << q.qName  << "),"
                << "Type("  << rtypes2string(q.qType)  << "),"
                << "Class(" << classes2string(q.qClass) << ")" << std::endl;
        }

        for (Answer* a : answers){
            std::cout << "Answer => "
                << "Name("  << a->aName      << "),"
                << "Type("  << rtypes2string(a->aType)    << "),"
                << "Class(" << classes2string(a->aClass)  << "),"
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
    std::string remote_ip;

    ssize_t relay(Package& package, uint8_t * res){

        ssize_t l;
        std::vector<uint8_t> vout = package.dump();
	    size_t out_size = vout.size();
	    std::string out(vout.begin(), vout.end());

        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in si_other;
	    socklen_t serverlen = sizeof(si_other);
	    memset((char *) &si_other, 0, sizeof(si_other));
        si_other.sin_family = AF_INET;
        si_other.sin_port = htons(53);
        inet_aton("8.8.8.8", &si_other.sin_addr);

	    sendto(sockfd, out.c_str(), out_size, 0, (struct sockaddr *) &si_other, serverlen);

	    memset(res, 0, BUF_SIZE);
	    l = recvfrom(sockfd, res, BUF_SIZE, 0, (struct sockaddr *) &si_other, &serverlen);
	    //std::vector<uint8_t> p(res, res + l);
        //print_hex(p);

        return l;
    }

    public:
    Resolver(Cache& cache):cache(cache){}
    void resolve(Package& package) {

        if (package.getFlagOPCode() == Package::Question_OpCode){
            for (Question q : package.questions){
                switch (q.qType){
                    case Package::A_Type:
                    case Package::CNAME_Type:
                        std::optional<std::vector<Answer*>> ret = cache.get(q);
                        if(ret){

                            std::cout << "Ta en cache :)" << std::endl;
                            package.answers  =  *ret;
                            package.ansCount = (*ret).size();

                        }else{

                            std::cout << "No ta en cache :(" << std::endl;
                            // Re-Send Package to a remote server.

                            uint8_t out[512];
                            relay(package, out);

                            Package response(out);
                            
                            // Save the answers of the Package Response in cache
                            if (response.getRCode() == Package::Ok_ResponseType){
                                cache.set(q, response.getAnswers());
                                for(Answer *a : response.answers){ 
                                    package.addAnswer(a->copy());
                                }
                            }

                            // So we don't want to free the answers in 
                            // the destructor of the Package Response

                            response.answers.clear();

                        }
                }
                break;
            }
        }else{
            package.setFlagRCode(Package::NotImplemented_ResponseType);
        }
        package.setFlagQR(Package::QR_Response);

    }

};

};