#include <emp-tool/emp-tool.h>
#include "emp-agmpc/emp-agmpc.h"

#include "emp-agmpc/flexible_input_output.h"

using namespace std;
using namespace emp;

const string filename = macro_xstr(EMP_CIRCUIT_PATH) + string("bristol_format/sha-256-multiblock-aligned.txt");

const static int nP = 2;
int party, port;

string sha256_init_vals = hex_to_binary("6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19");


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

void run_sha(int party, int port, string input) {
    
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
	for(int i = 0; i < cf.n1; i++) {
		in.assign_party(i, ALICE); 
	}
	
	FlexOut<nP> out(cf.n3, party);
	for(int i = 0; i < cf.n3; i++) {
		out.assign_party(i, 0); // public output
	}

    if (party == ALICE) {
        // SHA256 input
        for(int i = 0; i < 512; i++) {
            in.assign_plaintext_bit(i, input[i]=='1');
        }

        // Initial state
        unsigned int digest[8];
        digest[0] = 0x6A09E667L;
        digest[1] = 0xBB67AE85L;
        digest[2] = 0x3C6EF372L;
        digest[3] = 0xA54FF53AL;
        digest[4] = 0x510E527FL;
        digest[5] = 0x9B05688CL;
        digest[6] = 0x1F83D9ABL;
        digest[7] = 0x5BE0CD19L;

        for (int i = 0; i < 8; i++) {
            unsigned int tmp = digest[i];
            for (int j = 0; j < 32; j++) {
                in.assign_plaintext_bit(512 + i * 32 + j,  (tmp & 1)==1);
                tmp >>= 1;
            }
        }
        /*
        for(int i = 0; i < 256; i++) {
            in.assign_plaintext_bit(i+512, sha256_init_vals[i]=='1'); 
        }
        */
        

        for (int i=0; i<768; i++) {
            cout << in.plaintext_assignment[i] ? "1" : "0";
        }
        cout << endl;
    }

	mpc->online(&in, &out);
	ios[0]->flush();
	ios[1]->flush();
	
    string out_str;
    
    /***********************/
    for (int i = 0; i < 8; i++) {
		for (int j = 0; j < 4; j++) {
			int w = 1;
			for (int k = 0; k < 8; k++) {
				digest_char[i * 4 + j] += output_bool[i * 32 + 8 * j + k] * w;
				w <<= 1;
			}
		}
	}

	for (int i = 0; i < 32; i++) {
		printf("%02X ", digest_char[i]);
	}
    /************************/

    for (int i = 0; i < cf.n3; i++) {
        out_str += out.get_plaintext_bit(i)?"1":"0";
    }
    out_str = binary_to_hex(out_str);
    cout << out_str << endl;

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

    outdata << out_str << endl;
    outdata.close();
	delete mpc;
}

int main(int argc, char* argv[]) {
	parse_party_and_port(argv, &party, &port);

    std::string input = "";
    if (party == ALICE) {
        input = hex_to_binary(string(argv[3]));
    }
    cout << "INPUT: " << input << endl;
    //cout << "Key share: " << key_share << endl;
    //cout << "Plaintext: " << plaintext << endl;

    //string pt_share(argv[4]);
    //string counter(argv[5]);



	if(party > nP) return 0;
	
	run_sha(party, port, input);
	
	return 0;
}
