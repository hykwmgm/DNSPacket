#pragma once

using std::vector;
using std::string;

class DNSPacket {
private:
    vector<uint8_t> binary;
    H header;
    vector<Q> question;
    vector<RR> answer;
    vector<RR> authority;
    vector<RR> additional;

    void rrs_to_binary(const vector<RR> &rrs){
        for(const auto &rr: rrs){
            binary.insert(binary.end(), rr.name.begin(), rr.name.end());
            binary_to_8bits(rr.type, binary);
            binary_to_8bits(rr.Class, binary);
            binary_to_8bits(rr.ttl, binary);
            binary_to_8bits(rr.rdlen, binary);
            binary.insert(binary.end(), rr.rdata.begin(), rr.rdata.end());
        }
    }
    void read_rr(const int count, int &pos, vector<RR> &section){
        if(pos + 1 >= binary.size())
            return ;
        int size = binary.size();
        section.resize(count);
        for(int i = 0; i < count; i++){
            section[i].name = read_name(pos);
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
                    this->binary.begin() + pos,
                    this->binary.begin() + (pos + section[i].rdlen));
                pos += section[i].rdlen;
            }
        }
    }
    uint16_t read_u16(int& pos){
        uint16_t v = (static_cast<uint16_t>(binary[pos]) << 8) |
                     (static_cast<uint16_t>(binary[pos+1]));
        pos += 2;
        return v;
    }
    uint32_t read_u32(int& pos){
        uint32_t v = (static_cast<uint32_t>(binary[pos]) << 24) |
                     (static_cast<uint32_t>(binary[pos+1]) << 16) |
                     (static_cast<uint32_t>(binary[pos+2]) << 8 ) |
                     (static_cast<uint32_t>(binary[pos+3]));
        pos += 4;
        return v;
    }
    vector<uint8_t> read_name(
        const int& pos
        const int& limit = 16){
        vector<uint8_t> name;
        int now = pos;
        bool jumped = false;
        int depth = 0;

        while(now < binary.size()){
            uint8_t len = binary[now];
            if(len == 0x00){
                name.push_back(0x00);
                if(!jumped)
                    pos = now + 1;
                break;
            }
            if((len & 0xC0) == 0xC0){
                if(now + 1 >= binary.size())
                    return {};
                uint16_t pointer = ((len & 0x3F) << 8) | binary[now + 1];
                if(!jumped){
                    pos = now + 2;
                    jumped = true;
                }
                if(pointer >= now){
                    name.push_back(binary[now]);
                    name.push_back(binary[now + 1]);
                    return name;
                }
                    
                depth ++;
                now = pointer;
                continue;
            }else if(len > 63){
                name.push_back(len);
                return name;
            }
            if(depth > limit)
                return name;
            if(now + len > binary.size())
                return {};
            name.push_back(len);
            now++;
            for(int i = 0; i < len && now < binary.size(); i++, now++)
                name.push_back(binary[now]);
        }
        return name;
    }

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

    void binary_setter(const vector<uint8_t> &binary){ this->binary = binary; }
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

    const vector<uint8_t>& binary_getter() const { return binary; }
    const H& header_getter() const { return header; }
    const vector<Q>& question_getter() const { return question; }
    const vector<RR>& answer_getter() const { return answer; }
    const vector<RR>& authority_getter() const { return authority; }
    const vector<RR>& additional_getter() const { return additional; }

    void parameter_to_binary(void){
        binary.clear();
        binary_to_8bits(header.id, binary);
        binary_to_8bits(header.flags, binary);
        binary_to_8bits(header.qdcount, binary);
        binary_to_8bits(header.ancount, binary);
        binary_to_8bits(header.nscount, binary);
        binary_to_8bits(header.arcount, binary);

        for(const auto &q: question){
            binary.insert(binary.end(), q.name.begin(), q.name.end());
            binary_to_8bits(q.type, binary);
            binary_to_8bits(q.Class, binary);
        }
        rrs_to_binary(answer);
        rrs_to_binary(authority);
        rrs_to_binary(additional);

        return ;
    }
    void binary_to_parameter(void){
        question.clear();
        answer.clear();
        authority.clear();
        additional.clear();

        int pos = 0, size = binary.size();

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
        for(int i = 0; i < this->header.qdcount; i++){
            this->question[i].name = read_name(pos);
            if(pos + 1 < size)
                this->question[i].type = read_u16(pos);
            if(pos + 1 < size)
                this->question[i].Class = read_u16(pos);
        }
        
        read_rr(this->header.ancount, pos, answer);
        read_rr(this->header.nscount, pos, authority);
        read_rr(this->header.arcount, pos, additional);
    }

    vector<uint8_t> fqdn_string_to_binary(string before = ""){
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
    string fqdn_binary_to_string(const vector<uint8_t>& before) {
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
};
