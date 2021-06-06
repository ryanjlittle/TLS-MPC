#include <emp-tool/emp-tool.h>
#include "emp-agmpc/emp-agmpc.h"

#include "emp-agmpc/flexible_input_output.h"

using namespace std;
using namespace emp;

const string filename = macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_format/gcm_shares_10.txt");

const static int nP = 2;
int party, port;

inline const char byte_to_hex(string s) {
	if (s == "0000") return '0';
    if (s == "0000") return '0';
    if (s == "0001") return '1';
    if (s == "0010") return '2';
    if (s == "0011") return '3';
    if (s == "0100") return '4';
    if (s == "0101") return '5';
    if (s == "0110") return '6';
    if (s == "0111") return '7';
    if (s == "1000") return '8';
    if (s == "1001") return '9';
    if (s == "1010") return 'a';
    if (s == "1011") return 'b';
    if (s == "1100") return 'c';
    if (s == "1101") return 'd';
    if (s == "1110") return 'e';
    if (s == "1111") return 'f';
    return ' ';
}

inline string binary_to_hex(string bin) {
    string hex;
    for (unsigned i=0; i<bin.length(); i+=4) {
        hex += byte_to_hex(bin.substr(i,4));
    }
    return hex;
}


void run_gcmshare(int party, int port, string key_share) {
    
	NetIOMP<nP> io(party, port);
	NetIOMP<nP> io2(party, port+2*(nP+1)*(nP+1)+1);
	
	NetIOMP<nP> *ios[2] = {&io, &io2};
	ThreadPool pool(2*(nP-1)+2);
	
	BristolFormat cf(filename.c_str());
	
	CMPC<nP>* mpc = new CMPC<nP>(ios, &pool, party, &cf);
	ios[0]->flush();
	ios[1]->flush();
	
	mpc->function_independent();
	ios[0]->flush();
	ios[1]->flush();
	
	mpc->function_dependent();
	ios[0]->flush();
	ios[1]->flush();
	
	FlexIn<nP> in(cf.n1 + cf.n2, party);
    
    // The key is XORed between parties
	for(int i = 0; i < 128; i++) {
		in.assign_party(i, -2);
	}

	FlexOut<nP> out(cf.n3, party);

	for(int i = 0; i < cf.n3; i++) {
		out.assign_party(i, -1); //xored between parties 
        //out.assign_party(i,0); // public (for testing)
    }

    for (int i=0; i<128; i++) {
        in.assign_plaintext_bit(i, key_share[i]=='1');
    }
	
	mpc->online(&in, &out);
	ios[0]->flush();
	ios[1]->flush();
	
	
    string out_str;
    for (int i = 0; i < cf.n3; i++) {
        out_str += out.get_authenticated_bitshare(i).bit_share?"1":"0";
        //out_str += out.get_plaintext_bit(i)?"1":"0";

    }
    out_str = binary_to_hex(out_str);
    ofstream outdata;
    if (party==ALICE) {
        outdata.open("alice.out");
    } else {
        outdata.open("bob.out");
    }
    if (!outdata) {
        cerr << "File could not be opened" << endl; 
        exit(1);
    }

    //cout << out_str << endl;
    for (unsigned i=0; i<out_str.length(); i+=32) {
        outdata << out_str.substr(i, 32) << endl;
    }
    outdata.close();
	delete mpc;
}

int main(int argc, char* argv[]) {
	parse_party_and_port(argv, &party, &port);

    std::string key_share = hex_to_binary(string(argv[3]));

	if(party > nP) return 0;
	
	run_gcmshare(party, port, key_share);
	
	return 0;
}
