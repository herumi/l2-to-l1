#define MCLBN_FP_UNIT_SIZE 6
#define MCLBN_FR_UNIT_SIZE 4
#include <mcl/she.hpp>
#include <cybozu/socket.hpp>
#include <cybozu/serializer.hpp>
#include <cybozu/option.hpp>
#include <cybozu/time.hpp>
#include <fstream>
#include <thread>
#include <vector>
#include <time.h>
#include <omp.h>

using namespace mcl::she;
using namespace mcl::bn;

const char *g_secretKeyName = "secretkey.txt";

typedef std::vector<CipherTextGT> CipherTextGTVec;
typedef std::vector<CipherTextG1> CipherTextG1Vec;
typedef std::vector<int> IntVec;

template<class G>
void add(G& z, const G& x, const G& y)
{
	G::add(z, x, y);
}
template<class G>
void sub(G& z, const G& x, const G& y)
{
	G::sub(z, x, y);
}
template<class G, class T>
void mul(G& z, const G& x, const T& y)
{
	G::mul(z, x, y);
}

struct Timer {
	const char *msg_;
	double begin_;
	void begin(const char *msg)
	{
		msg_ = msg;
		begin_ = cybozu::GetCurrentTimeSec();
	}
	void end() const
	{
		printf("%s %.2f sec\n", msg_, cybozu::GetCurrentTimeSec() - begin_);
	}
};

void mulAddCipher(CipherTextG1& sum, const CipherTextG1 *cVec, size_t begin, size_t n, const IntVec& idxVec)
{
	assert(n > 0);
	int idx = idxVec[begin];
	sum = cVec[idx];
	mul(sum, sum, idx);
	for (size_t i = 1; i < n; i++) {
		idx = idxVec[begin + i];
		CipherTextG1 c;
		mul(c, cVec[idx], idx);
		add(sum, sum, c);
	}
}

void mulAddCipherAll(CipherTextG1& sum, const CipherTextG1 *cVec, size_t n, const IntVec& idxVec)
{
	const size_t threadN = 8;
	size_t q = n / threadN;
	if (q <= 1) {
		mulAddCipher(sum, cVec, 0, n, idxVec);
		return;
	}
	std::vector<std::unique_ptr<std::thread>> thVec(threadN);
	CipherTextG1 sumVec[threadN];
	for (size_t i = 0; i < threadN; i++) {
		size_t remain = (std::min)(n - q * i, q);
		thVec[i] = std::make_unique<std::thread>([&, i]{ mulAddCipher(sumVec[i], cVec, q * i, remain, idxVec); });
	}
	for (size_t i = 0; i < threadN; i++) {
		thVec[i]->join();
	}
	sum = sumVec[0];
	for (size_t i = 1; i < threadN; i++){
		add(sum, sum, sumVec[i]);
	}
}

void clientToServer(cybozu::Socket& soc, const SecretKey& sec, const PrecomputedPublicKey& ppub, const CipherTextGT& ct, size_t N)
{
	printf("N %zd\n", N);
	Timer tm;
	tm.begin("pre");
	CipherTextGTVec preCtVec(N);
	ppub.enc(preCtVec[0], 0);
	ppub.enc(preCtVec[1], 1);
	for (size_t i = 2; i < N; i++) {
		add(preCtVec[i], preCtVec[i - 1], preCtVec[1]);
	}
	tm.end();
	cybozu::save(soc, N);
	CipherTextGTVec ctVec(N);
	IntVec idxVec(N);
	cybozu::RandomGenerator rg;
	tm.begin("enc");
	for (size_t i = 0; i < N; i++) {
		idxVec[i] = int(i);
	}
	cybozu::shuffle(idxVec.data(), N, rg);
#pragma omp parallel for
	for (size_t i = 0; i < N; i++) {
		int idx = idxVec[i];
		CipherTextGT c;
		sub(c, ct, preCtVec[idx]);
		Fr gamma;
		gamma.setByCSPRNG();
		mul(ctVec[idx], c, gamma);
	}
	tm.end();
	tm.begin("send");
	soc.write(ctVec.data(), sizeof(ctVec[0]) * N);
	tm.end();

	tm.begin("re-enc+recv");
	CipherTextG1Vec c1Vec(N);
	soc.read(c1Vec.data(), sizeof(c1Vec[0]) * N);
	tm.end();

	tm.begin("dec");
	CipherTextG1 c1sum;
//	mulAddCipher(c1sum, c1Vec.data(), 0, N, idxVec);
	mulAddCipherAll(c1sum, c1Vec.data(), N, idxVec);
	tm.end();
	printf("dec=%d\n", (int)sec.dec(c1sum));
}

void serverToClient(cybozu::Socket& soc, const SecretKey& sec, const PrecomputedPublicKey& ppub)
{
	size_t N;
	cybozu::load(N, soc);
	printf("N=%zd\n", N);
	CipherTextGTVec ctVec(N);
	CipherTextG1Vec c1Vec(N);
	Timer tm;
	tm.begin("recv");
	soc.read(ctVec.data(), sizeof(ctVec[0]) * N);
	tm.end();
	tm.begin("re-enc");
#pragma omp parallel for
	for (size_t i = 0; i < N; i++) {
#if 0
		ppub.enc(sec.isZero(ctVec[i]) ? 1 : 0);
#else
		bool ok;
		sec.dec(ctVec[i], &ok);
		ppub.enc(c1Vec[i], ok ? 1 : 0);
#endif
	}
	tm.end();
	tm.begin("send");
	soc.write(c1Vec.data(), sizeof(c1Vec[0]) * N);
	tm.end();
}

int main(int argc, char *argv[])
	try
{
	cybozu::Option opt;
	int port;
	bool saveSecretKey;
	std::string ip;
	uint32_t m;
	size_t bitN;
	opt.appendOpt(&ip, "", "ip", ": ip address");
	opt.appendOpt(&port, 10000, "p", ": port");
	opt.appendOpt(&m, 5, "m", ": message");
	opt.appendOpt(&bitN, 3, "bitN", ": message space bit");
	opt.appendBoolOpt(&saveSecretKey, "save-sec", ": save secretKey");
	opt.appendHelp("h", "show this message");
	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 1;
	}
	const size_t N = size_t(1) << bitN;
	if (m >= N) {
		printf("m=%d must be in [0, %zd)\n", m, N);
		return 1;
	}
	const size_t tryNum = 1;
	mcl::she::init(mcl::BLS12_381, N, tryNum);
	verifyOrderG1(false);
	verifyOrderG2(false);

	if (saveSecretKey) {
		SecretKey sec;
		sec.setByCSPRNG();
		std::ofstream ofs(g_secretKeyName, std::ios::binary);
		sec.save(ofs);
		return 0;
	}
	SecretKey sec;
	{
		std::ifstream ifs(g_secretKeyName, std::ios::binary);
		sec.load(ifs);
	}
	PublicKey pub;
	sec.getPublicKey(pub);
	PrecomputedPublicKey ppub;
	ppub.init(pub);

	CipherTextGT ct;
	ppub.enc(ct, m);
	printf("m=%d, messageSpace=%zd\n", m, N);

	if (ip.empty()) {
		printf("server port=%d\n", port);
		cybozu::Socket server;
		server.bind(uint16_t(port));
		for (;;) {
			while (!server.queryAccept()) {
			}
			cybozu::Socket client;
			server.accept(client);
//			client.setSocketOption(TCP_NODELAY, 1, IPPROTO_TCP);
			serverToClient(client, sec, ppub);
		}
	} else {
		printf("client ip=%s port=%d\n", ip.c_str(), port);
		cybozu::SocketAddr sa(ip, uint16_t(port));
		printf("addr=%s\n", sa.toStr().c_str());
		cybozu::Socket client;
		client.connect(sa);
//		client.setSocketOption(TCP_NODELAY, 1, IPPROTO_TCP);
		clientToServer(client, sec, ppub, ct, N);
	}
} catch (std::exception& e) {
	printf("err %s\n", e.what());
	return 1;
}
