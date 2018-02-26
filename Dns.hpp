#include <cstdint>
#include <vector>
#include <cstring>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>

class DNS {

private:

    struct {
        uint16_t IS_RESPONSE = 0x8000;
    } FLAGS;

    struct Query {

        std::string qName;
        uint16_t qType;
        uint16_t qClass;
        Query(std::string qName, uint16_t qType, uint16_t qClass):
            qName(qName), qType(qType), qClass(qClass) {}

    };

    struct Answer {

        std::string aName;
        uint16_t aType;
        uint16_t aClass;
        uint32_t aTTL;
        uint8_t addr[4];

        Answer(std::string aName, uint16_t aType, uint16_t aClass, uint32_t aTTL):
            aName(aName), aType(aType), aClass(aClass), aTTL(aTTL) {}

        std::string addrToStr(){
            std::stringstream ip;
            ip  << int(addr[0]) << "." 
                << int(addr[1]) << "." 
                << int(addr[2]) << "." 
                << int(addr[3]);
            return ip.str();
        }

        void setAddr(uint8_t a, uint8_t b, uint8_t c, uint8_t d){
            addr[0] = a;
            addr[1] = b;
            addr[2] = c;
            addr[3] = d;
        }

    };

    struct {
        uint16_t id;
        uint16_t flags;
        uint16_t queCount;
        uint16_t ansCount;
        uint16_t autCount;
        uint16_t addCount;
        std::vector<Query> queries;
        std::vector<Answer> answers;
    } package;

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

    void put32bits(uint32_t value){
        value = htons(value);
        memcpy(out, &value, 4);
        out += 4;
    }

    void putDomain(std::string domain){

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

    std::string decodeDomain(){

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

    void parse(){

        package.id = get16bits();
        package.flags = get16bits();
        package.queCount = get16bits();
        package.ansCount = get16bits();
        package.autCount = get16bits();
        package.addCount = get16bits();
        std::string qDomain = decodeDomain();
        uint16_t qType = get16bits();
        uint16_t qClass = get16bits();

        for (int i = 0; i < package.queCount; ++i){
            package.queries.push_back(Query(
                qDomain,
                qType,
                qClass
            ));
        }

    }

    void setFlag(uint16_t mask){
        package.flags |= mask; 
    }

    void unsetFlag(uint16_t mask){
        package.flags &= ~mask; 
    }

public:
    DNS(uint8_t* buffer):buffer(buffer){
        parse();
    }

    void prettyPrint(){

        std::cout << "++++ DNS Package +++++" << std::endl;
        std::cout << "ID: " << package.id << std::endl;
        std::cout << "FLAG: " << package.flags << std::endl;
        std::cout << "Query Count: " << package.queCount << std::endl;
        std::cout << "Answer Count: " << package.ansCount << std::endl;
        std::cout << "Auth Count: " << package.autCount << std::endl;
        std::cout << "Additional: " << package.addCount << std::endl;

        for (Query q : package.queries){
            std::cout << "Query => "
                << "Name("  << q.qName  << "),"
                << "Type("  << q.qType  << "),"
                << "Class(" << q.qClass << ")" << std::endl;
        }

        for (Answer a : package.answers){
            std::cout << "Answer => "
                << "Name("  << a.aName      << "),"
                << "Type("  << a.aType      << "),"
                << "Class(" << a.aClass     << "),"
                << "TTL("   << a.aTTL       << ")"
                << "Addr("  << a.addrToStr()  << ")" << std::endl;
        }
    }

    void resolve(){
        for (Query q : package.queries){
            Answer answer(q.qName, q.qType, q.qClass, 0);
            answer.setAddr(192,168,1,1);
            package.answers.push_back(answer);
            package.ansCount++;
        }
        setFlag(FLAGS.IS_RESPONSE);
    }

    std::vector<uint8_t> dumpPackage(){

        uint8_t* start = new uint8_t[256];
        out = start;

        put16bits(package.id);
        put16bits(package.flags); 
        put16bits(package.queCount);
        put16bits(package.ansCount);
        put16bits(package.autCount);
        put16bits(package.addCount);

        for (Query q : package.queries){

            putDomain(q.qName);
            put16bits(q.qType);
            put16bits(q.qClass);

        }

        for (Answer a : package.answers){

            putDomain(a.aName);
            put16bits(a.aType);
            put16bits(a.aClass);
            put32bits(a.aTTL);
            put16bits(4);
            put8bits(a.addr[0]);
            put8bits(a.addr[1]);
            put8bits(a.addr[2]);
            put8bits(a.addr[3]);

        }

        std::vector<uint8_t> res(start, start + (out - start));
        delete[] start;
        return res;
    }

};

/*
void print_hex(std::vector <uint8_t> out) {

  printf("%zu bytes:\n", out.size());
  for(uint8_t e : out)
    printf("0x%02x ", e);
  printf("\n");

}

int main(){

    uint8_t trama[] = {
        0xf9,0xc1,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x77,0x77,0x77,0x08,
        0x66,0x61,0x63,0x65,0x62,0x6f,0x6f,0x6b,0x03,0x63,0x6f,0x6d,0x00,0x00,0x01,0x00,0x01
    };

    DNS dns(trama);
    dns.prettyPrint();
    dns.resolve();
    dns.prettyPrint();
    std::vector<uint8_t> out = dns.dumpPackage();

    print_hex(out);

    return 0;

}
*/