#pragma once

using std::vector;
using std::string;

class DNSPacket {
public:
    struct Header{
        uint16_t id = 0x0000;
        uint16_t flags = 0x0000;
        uint16_t qdcount = 0x0000;
        uint16_t ancount = 0x0000;
        uint16_t nscount = 0x0000;
        uint16_t arcount = 0x0000;
    };
    struct Question{
        vector<uint8_t> name = {0x00};
        uint16_t type = 0x0000;
        uint16_t Class = 0x0000;
    };
    struct ResourceRecord{
        vector<uint8_t> name = {0x00};
        uint16_t type = 0x0000;
        uint16_t Class = 0x0000;
        uint32_t ttl = 0x00000000;
        uint16_t rdlen = 0x0000;
        vector<uint8_t> rdata = {0x00};
    };

    using H = Header;
    using Q = Question;
    using RR = ResourceRecord;

    void octets_setter(const vector<uint8_t> &octets){ this->octets = octets; }
    void header_setter(
        const H &header,
        int id = -1){
        this->header = header;
        if(id >= 0 && id <= 65535)
            this->header.id = id;
        else{
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint16_t> dist;
            this->header.id = dist(gen);
        }
    }
    void question_setter(const vector<Q>& question){ this->question = question; }
    void answer_setter(const vector<RR>& answer){ this->answer = answer; }
    void authority_setter(const vector<RR>& authority){ this->authority = authority; }
    void additional_setter(const vector<RR>& additional){ this->additional = additional; }

    const vector<uint8_t>& octets_getter() const { return octets; }
    const H& header_getter() const { return header; }
    const vector<Q>& question_getter() const { return question; }
    const vector<RR>& answer_getter() const { return answer; }
    const vector<RR>& authority_getter() const { return authority; }
    const vector<RR>& additional_getter() const { return additional; }

    void parameter_to_octets(void){
        octets.clear();
        octets_to_8bits(header.id, octets);
        octets_to_8bits(header.flags, octets);
        octets_to_8bits(header.qdcount, octets);
        octets_to_8bits(header.ancount, octets);
        octets_to_8bits(header.nscount, octets);
        octets_to_8bits(header.arcount, octets);

        for(const auto &q: question){
            octets.insert(octets.end(), q.name.begin(), q.name.end());
            octets_to_8bits(q.type, octets);
            octets_to_8bits(q.Class, octets);
        }
        rrs_to_octets(answer);
        rrs_to_octets(authority);
        rrs_to_octets(additional);

        return ;
    }
    void octets_to_parameter(void){
        question.clear();
        answer.clear();
        authority.clear();
        additional.clear();

        int pos = 0, size = octets.size();

        if(pos + 1 < size)
            this->header.id = read_u16(pos);
        if(pos + 1 < size)
            this->header.flags = read_u16(pos);
        if(pos + 1 < size)
            this->header.qdcount = read_u16(pos);
        if(pos + 1 < size)
            this->header.ancount = read_u16(pos);
        if(pos + 1 < size)
            this->header.nscount = read_u16(pos);
        if(pos + 1 < size)
            this->header.arcount = read_u16(pos);
        
        this->question.resize(this->header.qdcount);
        bool is_invalid = false;
        for(int i = 0; i < this->header.qdcount; i++){
            this->question[i].name = read_name(is_invalid, pos);
            if(is_invalid)
                return ;
            if(pos + 1 < size)
                this->question[i].type = read_u16(pos);
            if(pos + 1 < size)
                this->question[i].Class = read_u16(pos);
        }
        
        read_rr(this->header.ancount, pos, answer);
        read_rr(this->header.nscount, pos, authority);
        read_rr(this->header.arcount, pos, additional);
    }
    vector<uint8_t> fqdn_string_to_octets(string before = ""){
        if(before.empty())
            return {};
        vector<uint8_t> after = {};
        vector<uint8_t> temp = {};
        int len = 0;
        if(before.back() != '.')
            before.push_back('.');
        for(char c: before){
            if(c == '.'){
                after.push_back(len);
                after.insert(after.end(), temp.begin(), temp.end());
                temp.clear();
                len = 0;
            }
            else{
                temp.push_back(static_cast<uint8_t>(c));
                len ++;
            }
            if(len > 63)
                return {};
        }
        after.push_back(0x00);

        if (after.size() > 255)
            return {};

        return after;
    }
    string fqdn_octets_to_string(const vector<uint8_t>& before) {
        if (before.empty())
            return "";
        if (before[0] == 0x00)
            return ".";

        string after;
        size_t i = 0;
        while (i < before.size() && before[i] != 0x00) {
            uint8_t len = before[i];
            ++i;

            after.append(reinterpret_cast<const char*>(before.data() + i), len);
            after += '.';
            i += len;
        }

        return after;
    }
    void print_parameter(void){
        std::cout << "id: " << header.id << "\n";
        std::cout << "flags: " << header.flags << "\n";
        std::cout << "qdcount: " << header.qdcount << "\n";
        std::cout << "ancount: " << header.ancount << "\n";
        std::cout << "nscount: " << header.nscount << "\n";
        std::cout << "arcount: " << header.arcount << "\n";
        
        for(int i = 0; i < question.size(); i++){
            std::cout << "question" << i <<":\n";
            std::cout << "name: "; print_octets(question[i].name);
            std::cout << "type: " << question[i].type << "\n";
            std::cout << "class: " << question[i].Class << "\n";
        }

        std::cout << "answer:\n";
        print_RRs(answer);
        std::cout << "authority:\n";
        print_RRs(authority);
        std::cout << "additional:\n";
        print_RRs(additional);
        std::cout << "octets:\n";
        print_octets(octets);
    }

private:
    vector<uint8_t> octets;
    H header;
    vector<Q> question;
    vector<RR> answer;
    vector<RR> authority;
    vector<RR> additional;

    void rrs_to_octets(const vector<RR> &rrs){
        for(const auto &rr: rrs){
            octets.insert(octets.end(), rr.name.begin(), rr.name.end());
            octets_to_8bits(rr.type, octets);
            octets_to_8bits(rr.Class, octets);
            octets_to_8bits(rr.ttl, octets);
            octets_to_8bits(rr.rdlen, octets);
            octets.insert(octets.end(), rr.rdata.begin(), rr.rdata.end());
        }
    }
    void read_rr(const int count, int &pos, vector<RR> &section){
        if(pos + 1 >= octets.size())
            return ;
        int size = octets.size();
        section.resize(count);
        bool is_invalid = false;
        for(int i = 0; i < count; i++){
            section[i].name = read_name(is_invalid,pos);
            if(is_invalid)
                return ;
            if(pos + 1 < size)
                section[i].type = read_u16(pos);
            if(pos + 1 < size)
                section[i].Class = read_u16(pos);
            if(pos + 3 < size)
                section[i].ttl = read_u32(pos);
            if(pos + 1 < size)
                section[i].rdlen = read_u16(pos);
            if(pos + section[i].rdlen <= size){
                section[i].rdata.assign(
                    this->octets.begin() + pos,
                    this->octets.begin() + (pos + section[i].rdlen));
                pos += section[i].rdlen;
            }
        }
    }
    uint16_t read_u16(int& pos){
        uint16_t v = (static_cast<uint16_t>(octets[pos]) << 8) |
                     (static_cast<uint16_t>(octets[pos+1]));
        pos += 2;
        return v;
    }
    uint32_t read_u32(int& pos){
        uint32_t v = (static_cast<uint32_t>(octets[pos]) << 24) |
                     (static_cast<uint32_t>(octets[pos+1]) << 16) |
                     (static_cast<uint32_t>(octets[pos+2]) << 8 ) |
                     (static_cast<uint32_t>(octets[pos+3]));
        pos += 4;
        return v;
    }
    vector<uint8_t> read_name(
        bool &is_invalid,
        int& pos,
        const int& limit = 16){
        vector<uint8_t> name;
        int now = pos, depth = 0, total_len = 0;
        bool jumped = false;
        while(now < octets.size()){
            uint8_t len = octets[now];
            if(len == 0x00){
                name.push_back(0x00);
                if(!jumped)
                    pos = now + 1;
                total_len ++;
                break;
            }else{
                total_len += len + 1;
            }
            if((len & 0xC0) == 0xC0){
                if(now + 1 >= octets.size()){
                    is_invalid = true;
                    return {};
                }
                uint16_t pointer = ((len & 0x3F) << 8) | octets[now + 1];
                if(!jumped){
                    pos = now + 2;
                    jumped = true;
                }
                if(pointer >= now){
                    name.push_back(octets[now]);
                    name.push_back(octets[now + 1]);
                    is_invalid = true;
                    return name;
                }
                    
                if(++depth > limit){
                    is_invalid = true;
                    return name;
                }
                now = pointer;
                continue;
            }else if(len > 63){
                name.push_back(len);
                is_invalid = true;
                return name;
            }
            if(now + 1 + len > octets.size()){
                is_invalid = true;
                return {};
            }
            name.push_back(len);
            now++;
            for(int i = 0; i < len && now < octets.size(); i++, now++)
                name.push_back(octets[now]);
        }
        if(total_len > 255)
            name.push_back(total_len);
        return name;
    }
    void print_RRs(const vector<RR>& rrs){
        for(int i = 0; i < rrs.size(); i++){
            std::cout << "rr" << i <<":\n";
            std::cout << "name: "; print_octets(rrs[i].name);
            std::cout << "type: " << rrs[i].type << "\n";
            std::cout << "class: " << rrs[i].Class << "\n";
            std::cout << "ttl: " << rrs[i].ttl << "\n";
            std::cout << "rdlen: " << rrs[i].rdlen << "\n";
            std::cout << "rdata: "; print_octets(rrs[i].rdata);
        }
    }
    void print_octets(const std::vector<uint8_t>& v){
        int size = v.size();
        std::cout << std::hex;
        for (int i = 0; i < v.size(); i++){
            std::cout << std::setw(2) << std::setfill('0')<< static_cast<int>(v[i])<< ' ';
            if((i+1) % 10 == 0)
                std::cout << '\n';
        }
        std::cout << std::dec << '\n';
    }

};
